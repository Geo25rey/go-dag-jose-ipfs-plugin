package dagJoseIpfsPlugin

import (
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
	"github.com/ipld/go-ipld-prime/codec/dagcbor"
	jsonCodec "github.com/ipld/go-ipld-prime/codec/json"
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
		fmt.Print(b)
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
	err = dagcbor.Decode(nodeBuilder, buf)
	if err != nil {
		fmt.Println("dagjose: Failed to decode:", err)
		return
	}

	primeNode := nodeBuilder.Build()
	printNode(primeNode)
	fmt.Println("dagjose: Successfully decoded node")
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
	}
	return
}

func noopDecode(na prime.NodeAssembler, r io.Reader) error {
	return nil
}

func encoder(r io.Reader, mhType uint64, mhLen int, decoder prime.Decoder) (result []ipld.Node, err error) {
	// ignore mhLen=-1 since values are nosensical
	if mhType == math.MaxUint64 {
		mhType = mh.SHA2_256
	}

	inBuf, err := ioutil.ReadAll(r)
	if err == io.EOF {
		inBuf = make([]byte, 0)
	} else if err != nil {
		fmt.Println("dagjose: Failed to encode:", err)
		return
	}

	fmt.Println("dagjose: debug input:", string(inBuf))
	primeNode, err := parseJOSE(inBuf)
	if err != nil {
		fmt.Println("dagjose: Failed to encode:", err)
		return
	}
	err = printNode(primeNode)
	if err != nil {
		fmt.Println(err)
	}

	outBuf := &bytes.Buffer{}
	if err = dagcbor.Encode(primeNode, outBuf); err != nil {
		fmt.Println("dagjose: Failed to encode:", err)
		return
	}
	// fmt.Println(outBuf.String())
	fmt.Println(outBuf.Bytes())

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

	printNode(primeNode)
	legacyNode := &legacy.LegacyNode{
		Block: block,
		Node:  primeNode,
	}
	err = nil
	result = []ipld.Node{legacyNode}
	fmt.Println("dagjose: Successfully encoded node")
	return
}

func encoderBuilder(inputEncoding string) coredag.DagParser {
	switch inputEncoding {
	case "raw":
		return func(r io.Reader, mhType uint64, mhLen int) ([]ipld.Node, error) {
			return encoder(r, mhType, mhLen, jsonCodec.Decode)
		}
	default:
		return func(r io.Reader, mhType uint64, mhLen int) ([]ipld.Node, error) {
			return encoder(r, mhType, mhLen, noopDecode)
		}
	}
}

var (
	inputEncodings []string = []string{
		"raw",
		"json",
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
