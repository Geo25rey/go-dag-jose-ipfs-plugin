package example

import (
	"github.com/Geo25rey/go-dag-jose/dagjose"
	blocks "github.com/ipfs/go-block-format"
	"github.com/ipfs/go-ipfs/core/coredag"
	"github.com/ipfs/go-ipfs/plugin"
	ipld "github.com/ipfs/go-ipld-format"
	legacy "github.com/ipfs/go-ipld-legacy"
	dagcbor "github.com/ipld/go-ipld-prime/codec/dagcbor"

	"bytes"
	"io"
	"io/ioutil"
)

type ipldDagJose struct{}

// Plugins is an exported list of plugins that will be loaded by go-ipfs.
var Plugins = []plugin.Plugin{
	&ipldDagJose{},
}

func decoder(block blocks.Block) (ipld.Node, error) {
	nodeBuilder := dagjose.NewBuilder()
	buf := bytes.NewBuffer(block.RawData())
	err := dagcbor.Decode(nodeBuilder, buf)
	if err != nil {
		println("Failed to decode:", err)
		return nil, err
	}
	primeNode := nodeBuilder.Build()
	println("Decode success")
	return &legacy.LegacyNode{
		Block: block,
		Node:  primeNode,
	}, nil
}

func (dagJose *ipldDagJose) RegisterBlockDecoders(dec ipld.BlockDecoder) error {
	dec.Register(0x85, decoder)
	return nil
}

func encoder(r io.Reader, mhType uint64, mhLen int) (result []ipld.Node, err error) {
	if mhType != 0x15 || mhLen != 48 {
		println("mhType=", mhType)
		println("mhLen=", mhLen)
		println("mhType or mhLen doesn't match")
		return
	}
	buf, err := ioutil.ReadAll(r)
	if err != nil {
		println("Error from read:", err)
		return
	}
	nodeBuilder := dagjose.NewBuilder()
	err = nodeBuilder.AssignBytes(buf)
	if err != nil {
		println("Error from building:", err)
		return
	}
	primeNode := nodeBuilder.Build()
	block := blocks.NewBlock(buf)
	legacyNode := &legacy.LegacyNode{
		Block: block,
		Node:  primeNode,
	}
	err = nil
	result = []ipld.Node{legacyNode}
	println("Successfully built node")
	return
}

var (
	inputEncodings []string = []string{
		"raw",
	}
	formats []string = []string{
		"dag-jose",
	}
)

func (dagJose *ipldDagJose) RegisterInputEncParsers(iec coredag.InputEncParsers) error {
	for _, inputEncoding := range inputEncodings {
		for _, format := range formats {
			iec.AddParser(inputEncoding, format, encoder)
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
