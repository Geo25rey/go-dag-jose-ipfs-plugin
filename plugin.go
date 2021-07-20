package dagJoseIpfsPlugin

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"

	"github.com/Geo25rey/go-dag-jose/dagjose"
	blocks "github.com/ipfs/go-block-format"
	cid "github.com/ipfs/go-cid"
	"github.com/ipfs/go-ipfs/core/coredag"
	"github.com/ipfs/go-ipfs/plugin"
	ipld "github.com/ipfs/go-ipld-format"
	legacy "github.com/ipfs/go-ipld-legacy"
	prime "github.com/ipld/go-ipld-prime"
	"github.com/ipld/go-ipld-prime/codec/cbor"
	mh "github.com/multiformats/go-multihash"

	"bytes"
	"io"
)

type ipldDagJose struct{}

// Plugins is an exported list of plugins that will be loaded by go-ipfs.
var Plugins = []plugin.Plugin{
	&ipldDagJose{},
}

var DAG_JOSE_CODEC uint64 = 0x85

func printNodeIndexed(node prime.Node, depth int) error {
	switch node.Kind() {
	case prime.Kind_Map:
		fmt.Println("{")
		it := node.MapIterator()
		for !it.Done() {
			key, value, err := it.Next()
			if err != nil {
				return err
			}
			keyStr, err := key.AsString()
			if err != nil {
				return err
			}
			for i := 0; i < depth+1; i++ {
				fmt.Print("    ")
			}
			fmt.Printf("\"%v\": ", keyStr)
			err = printNodeIndexed(value, depth+1)
			if err != nil {
				return err
			}
			fmt.Println(",")
		}
		for i := 0; i < depth; i++ {
			fmt.Print("    ")
		}
		fmt.Print("}")
	case prime.Kind_List:
		fmt.Println("[")
		it := node.ListIterator()
		for !it.Done() {
			_, value, err := it.Next()
			if err != nil {
				return err
			}
			for i := 0; i < depth+1; i++ {
				fmt.Print("    ")
			}
			err = printNodeIndexed(value, depth+1)
			if err != nil {
				return err
			}
			fmt.Println(",")
		}
		for i := 0; i < depth; i++ {
			fmt.Print("    ")
		}
		fmt.Print("]")
	case prime.Kind_Bool:
		fmt.Print(node.AsBool())
	case prime.Kind_Float:
		fmt.Print(node.AsFloat())
	case prime.Kind_Bytes:
		b, err := node.AsBytes()
		if err != nil {
			return err
		}
		encodedString := base64.RawURLEncoding.EncodeToString(b)
		fmt.Print('"', encodedString, '"')
	case prime.Kind_Int:
		fmt.Print(node.AsInt())
	case prime.Kind_String:
		str, err := node.AsString()
		if err != nil {
			return err
		}
		fmt.Printf("\"%v\"", str)
	case prime.Kind_Null:
		fmt.Print("null")
	case prime.Kind_Link:
		link, err := node.AsLink()
		if err != nil {
			return err
		}
		fmt.Printf("\"%v\"", link.String())
	case prime.Kind_Invalid:
		fmt.Print("invalid")
	}
	return nil
}

func printNode(node prime.Node) error {
	return printNodeIndexed(node, 0)
}

func decoder(block blocks.Block) (result ipld.Node, err error) {
	nodeBuilder := dagjose.NewBuilder()
	buf := bytes.NewBuffer(block.RawData())
	err = cbor.Decode(nodeBuilder, buf)
	if err != nil {
		fmt.Printf("dagjose: Failed to decode as DAG-CBOR %v", err)
		return
	}

	primeNode := nodeBuilder.Build()
	err = nil
	result = &legacy.LegacyNode{
		Block: block,
		Node:  primeNode,
	}
	return
}

func (dagJose *ipldDagJose) RegisterBlockDecoders(dec ipld.BlockDecoder) error {
	dec.Register(DAG_JOSE_CODEC, decoder)
	return nil
}

func parseJOSE(jsonStr []byte) (result prime.Node, err error) {
	var rawJws struct {
		Payload    *string `json:"payload"`
		CipherText *string `json:"ciphertext"`
	}
	if err := json.Unmarshal(jsonStr, &rawJws); err != nil {
		return nil, fmt.Errorf("error parsing unknown json: %v", err)
	}

	fmt.Println(string(jsonStr))

	if rawJws.Payload != nil {
		var dagJWS *dagjose.DagJWS
		dagJWS, err = dagjose.ParseJWS(jsonStr)
		fmt.Println(string(dagJWS.GeneralJSONSerialization()))
		if err != nil {
			return
		}
		result = dagJWS.AsJOSE().AsNode()
		sigs, _ := result.LookupByString("signatures")
		fmt.Println(sigs)
	} else if rawJws.CipherText != nil {
		var dagJWE *dagjose.DagJWE
		dagJWE, err = dagjose.ParseJWE(jsonStr)
		fmt.Println(dagJWE.AsJOSE())
		if err != nil {
			return
		}
		result = dagJWE.AsJOSE().AsNode()
	} else {
		return nil, fmt.Errorf("no payload or ciphertext found")
	}
	return
}

func buildNodeFromJSON(input io.Reader) (result prime.Node, err error) {
	var jsonStr []byte
	jsonStr, err = ioutil.ReadAll(input)
	if err != nil {
		return
	}
	result, err = parseJOSE(jsonStr)
	if err != nil {
		return
	}
	return
}

type InputDecoder prime.Decoder

func buildNodeFromInputDecoder(r io.Reader, inputDecoder InputDecoder) (result prime.Node, err error) {
	nodeBuilder := dagjose.NewBuilder()
	err = inputDecoder(nodeBuilder, r)
	if err != nil {
		fmt.Println("dagjose: Failed to encode:", err)
		return
	}

	primeNode := nodeBuilder.Build()
	return primeNode, nil
}

func encoder(primeNode prime.Node, mhType uint64, mhLen int) (result []ipld.Node, err error) {
	// ignore mhLen=-1 since values are nosensical
	if mhType == math.MaxUint64 {
		mhType = mh.SHA2_256
	}

	outBuf := &bytes.Buffer{}
	if err = cbor.Encode(primeNode, outBuf); err != nil {
		fmt.Println("dagjose: Failed to encode:", err)
		return
	}

	hash, err := mh.Sum(outBuf.Bytes(), mhType, mhLen)
	if err != nil {
		fmt.Println("dagjose: Failed to encode:", err)
		return
	}
	c := cid.NewCidV1(DAG_JOSE_CODEC, hash)

	block, err := blocks.NewBlockWithCid(outBuf.Bytes(), c)
	if err != nil {
		fmt.Println("dagjose: Failed to encode:", err)
		return
	}

	legacyNode := &legacy.LegacyNode{
		Block: block,
		Node:  primeNode,
	}
	err = nil
	result = []ipld.Node{legacyNode}
	return
}

func encoderBuilder(inputEncoding string) coredag.DagParser {
	switch inputEncoding {
	case "cbor":
		fallthrough
	case "raw":
		return func(r io.Reader, mhType uint64, mhLen int) ([]ipld.Node, error) {
			primeNode, err := buildNodeFromInputDecoder(r, cbor.Decode)
			if err != nil {
				return nil, err
			}
			return encoder(primeNode, mhType, mhLen)
		}
	case "json":
		return func(r io.Reader, mhType uint64, mhLen int) ([]ipld.Node, error) {
			primeNode, err := buildNodeFromJSON(r)
			if err != nil {
				return nil, err
			}
			return encoder(primeNode, mhType, mhLen)
		}
	default:
		return func(r io.Reader, mhType uint64, mhLen int) ([]ipld.Node, error) {
			return nil, fmt.Errorf("unknown input encoding: %s", inputEncoding)
		}
	}
}

var (
	inputEncodings []string = []string{
		"raw",
		"json",
		"cbor",
	}
	formats []string = []string{
		"dag-jose",
	}
)

func (dagJose *ipldDagJose) RegisterInputEncParsers(iec coredag.InputEncParsers) error {
	for _, inputEncoding := range inputEncodings {
		for _, format := range formats {
			iec.AddParser(inputEncoding, format, encoderBuilder(inputEncoding))
		}
	}
	return nil
}

func (dagJose *ipldDagJose) Name() string {
	return "ipldDagJose"
}

func (dagJose *ipldDagJose) Version() string {
	return "0.1.0"
}

func (dagJose *ipldDagJose) Init(env *plugin.Environment) error {
	return nil
}
