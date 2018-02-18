/*

This package specifies the application's interface to the the BlockArt
library (blockartlib) to be used in project 1 of UBC CS 416 2017W2.

*/

package blockartlib

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net/rpc"
	"os"
	"regexp"
	"strings"
)

// Represents a type of shape in the BlockArt system.
type ShapeType int

const (
	// Path shape.
	PATH ShapeType = iota

	// Circle shape (extra credit).
	// CIRCLE
)

// Settings for a canvas in BlockArt.
type CanvasSettings struct {
	// Canvas dimensions
	CanvasXMax uint32
	CanvasYMax uint32
}

// Settings for an instance of the BlockArt project/network.
type MinerNetSettings struct {
	// Hash of the very first (empty) block in the chain.
	GenesisBlockHash string

	// The minimum number of ink miners that an ink miner should be
	// connected to. If the ink miner dips below this number, then
	// they have to retrieve more nodes from the server using
	// GetNodes().
	MinNumMinerConnections uint8

	// Mining ink reward per op and no-op blocks (>= 1)
	InkPerOpBlock   uint32
	InkPerNoOpBlock uint32

	// Number of milliseconds between heartbeat messages to the server.
	HeartBeat uint32

	// Proof of work difficulty: number of zeroes in prefix (>=0)
	PoWDifficultyOpBlock   uint8
	PoWDifficultyNoOpBlock uint8

	// Canvas settings
	canvasSettings CanvasSettings
}

type MyCanvas struct {
	conn           *rpc.Client
	minerPrivKey   ecdsa.PrivateKey
	CanvSetting    CanvasSettings
	artnodePrivKey string
}

type ValidMiner struct {
	CanvSetting CanvasSettings
	Valid       bool
}

////////////////////////////////////////////////////////////////////////////////////////////
// <ERROR DEFINITIONS>

// These type definitions allow the application to explicitly check
// for the kind of error that occurred. Each API call below lists the
// errors that it is allowed to raise.
//
// Also see:
// https://blog.golang.org/error-handling-and-go
// https://blog.golang.org/errors-are-values

// Contains address IP:port that art node cannot connect to.
type DisconnectedError string

func (e DisconnectedError) Error() string {
	return fmt.Sprintf("BlockArt: cannot connect to [%s]", string(e))
}

// Contains amount of ink remaining.
type InsufficientInkError uint32

func (e InsufficientInkError) Error() string {
	return fmt.Sprintf("BlockArt: Not enough ink to addShape [%d]", uint32(e))
}

// Contains the offending svg string.
type InvalidShapeSvgStringError string

func (e InvalidShapeSvgStringError) Error() string {
	return fmt.Sprintf("BlockArt: Bad shape svg string [%s]", string(e))
}

// Contains the offending svg string.
type ShapeSvgStringTooLongError string

func (e ShapeSvgStringTooLongError) Error() string {
	return fmt.Sprintf("BlockArt: Shape svg string too long [%s]", string(e))
}

// Contains the bad shape hash string.
type InvalidShapeHashError string

func (e InvalidShapeHashError) Error() string {
	return fmt.Sprintf("BlockArt: Invalid shape hash [%s]", string(e))
}

// Contains the bad shape hash string.
type ShapeOwnerError string

func (e ShapeOwnerError) Error() string {
	return fmt.Sprintf("BlockArt: Shape owned by someone else [%s]", string(e))
}

// Empty
type OutOfBoundsError struct{}

func (e OutOfBoundsError) Error() string {
	return fmt.Sprintf("BlockArt: Shape is outside the bounds of the canvas")
}

// Contains the hash of the shape that this shape overlaps with.
type ShapeOverlapError string

func (e ShapeOverlapError) Error() string {
	return fmt.Sprintf("BlockArt: Shape overlaps with a previously added shape [%s]", string(e))
}

// Contains the invalid block hash.
type InvalidBlockHashError string

func (e InvalidBlockHashError) Error() string {
	return fmt.Sprintf("BlockArt: Invalid block hash [%s]", string(e))
}

// Contains the invalid miner's private/public key
type InvalidMinerPKError string

func (e InvalidMinerPKError) Error() string {
	return fmt.Sprintf("BlockArt: Invalid miner's private/public key [%s]", string(e))
}

// </ERROR DEFINITIONS>
////////////////////////////////////////////////////////////////////////////////////////////

// Represents a canvas in the system.
type Canvas interface {
	// Adds a new shape to the canvas.
	// Can return the following errors:
	// - DisconnectedError
	// - InsufficientInkError
	// - InvalidShapeSvgStringError
	// - ShapeSvgStringTooLongError
	// - ShapeOverlapError
	// - OutOfBoundsError
	AddShape(validateNum uint8, shapeType ShapeType, shapeSvgString string, fill string, stroke string) (shapeHash string, blockHash string, inkRemaining uint32, err error)

	// Returns the encoding of the shape as an svg string.
	// Can return the following errors:
	// - DisconnectedError
	// - InvalidShapeHashError
	GetSvgString(shapeHash string) (svgString string, err error)

	// Returns the amount of ink currently available.
	// Can return the following errors:
	// - DisconnectedError
	GetInk() (inkRemaining uint32, err error)

	// Removes a shape from the canvas.
	// Can return the following errors:
	// - DisconnectedError
	// - ShapeOwnerError
	DeleteShape(validateNum uint8, shapeHash string) (inkRemaining uint32, err error)

	// Retrieves hashes contained by a specific block.
	// Can return the following errors:
	// - DisconnectedError
	// - InvalidBlockHashError
	GetShapes(blockHash string) (shapeHashes []string, err error)

	// Returns the block hash of the genesis block.
	// Can return the following errors:
	// - DisconnectedError
	GetGenesisBlock() (blockHash string, err error)

	// Retrieves the children blocks of the block identified by blockHash.
	// Can return the following errors:
	// - DisconnectedError
	// - InvalidBlockHashError
	GetChildren(blockHash string) (blockHashes []string, err error)

	// Closes the canvas/connection to the BlockArt network.
	// - DisconnectedError
	CloseCanvas() (inkRemaining uint32, err error)
}

type AddShapeStruct struct {
	ValidateNum    uint8
	SType          ShapeType
	ShapeSvgString string
	Fill           string
	Stroke         string
	ArtNodePK      string
}

type AddShapeReply struct {
	ShapeHash    string
	BlockHash    string
	InkRemaining uint32
}

type DelShapeArgs struct {
	ValidateNum uint8
	ShapeHash   string
	ArtNodePK   string
}

type CloseCanvReply struct {
	CanvOps      map[string][]string
	InkRemaining uint32
}

type Operation struct {
	AppShape      string
	OpSig         string
	PubKeyArtNode string //key of the art node that generated the op
	ShapeCommand  string // e.g. "M 0 0 L 0 3"
	ShapeFill     string // fill or transparent
}

// The constructor for a new Canvas object instance. Takes the miner's
// IP:port address string and a public-private key pair (ecdsa private
// key type contains the public key). Returns a Canvas instance that
// can be used for all future interactions with blockartlib.
//
// The returned Canvas instance is a singleton: an application is
// expected to interact with just one Canvas instance at a time.
//
// Can return the following errors:
// - DisconnectedError
func OpenCanvas(minerAddr string, privKey ecdsa.PrivateKey) (canvas Canvas, setting CanvasSettings, err error) {

	c, err := rpc.Dial("tcp", minerAddr)
	if err != nil {
		return canvas, CanvasSettings{}, DisconnectedError("rpc dial")
	}

	artnodePK, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	var validMiner *ValidMiner
	validMiner = &ValidMiner{}
	privKeyInString := getPrivKeyInStr(privKey)
	err = c.Call("InkMinerRPC.Connect", privKeyInString, &validMiner)

	//println("2", (*validMiner).Valid)
	// return canvas, CanvasSettings{}, InvalidShapeSvgStringError("ss")
	if !(*validMiner).Valid {
		return canvas, CanvasSettings{}, DisconnectedError("invalid miner key")
	}

	if err != nil {
		return canvas, CanvasSettings{}, DisconnectedError("InkMinerRPC.Connect")
	}
	//println("3")
	setting = (*validMiner).CanvSetting

	//println("4")
	artPkinStr := getPrivKeyInStr(*artnodePK)
	canv := MyCanvas{c, privKey, (*validMiner).CanvSetting, artPkinStr}
	//fmt.Println("PPPPPPPPPPPPPP###", (*validMiner).CanvSetting)
	canvas = &canv
	return canvas, setting, err
}

//======================================================================
//API implementation:
//======================================================================

// Adds a new shape to the canvas.
// Can return the following errors:
// - DisconnectedError
// - InsufficientInkError
// - InvalidShapeSvgStringError
// - ShapeSvgStringTooLongError
// - ShapeOverlapError
// - OutOfBoundsError
func (c *MyCanvas) AddShape(validateNum uint8, shapeType ShapeType, shapeSvgString string, fill string, stroke string) (shapeHash string, blockHash string, inkRemaining uint32, err error) {
	if len(shapeSvgString) > 128 {
		return "", "", 0, ShapeSvgStringTooLongError(shapeSvgString)
	}
	if stroke == fill && fill == "transparent" {
		println("-----------------------------------------------------")
		return "", "", 0, InvalidShapeSvgStringError("fill and stroke can't both be transparent")
	}
	// err1 := validSvgCommand(shapeSvgString)
	// if err1 != nil {
	// 	return "", "", 0, err1
	// }

	// mpk := getPrivKeyInStr(c.minerPrivKey)

	args := AddShapeStruct{1, shapeType, shapeSvgString, fill, stroke, c.artnodePrivKey}
	reply := AddShapeReply{}
	err = c.conn.Call("InkMinerRPC.AddShape", args, &reply)
	// fmt.Println("@@@", reply.ShapeHash)
	return reply.ShapeHash, reply.BlockHash, reply.InkRemaining, err
}

// Returns the encoding of the shape as an svg string.
// Can return the following errors:
// - DisconnectedError
// - InvalidShapeHashError
func (c *MyCanvas) GetSvgString(shapeHash string) (svgString string, err error) {
	var reply string
	err = c.conn.Call("InkMinerRPC.GetSvgString", shapeHash, &reply)
	svgString = reply
	return svgString, err
}

// Returns the amount of ink currently available.
// Can return the following errors:
// - DisconnectedError
func (c *MyCanvas) GetInk() (inkRemaining uint32, err error) {
	mpk := getPrivKeyInStr(c.minerPrivKey)
	err = c.conn.Call("InkMinerRPC.GetInk", mpk, &inkRemaining)
	return inkRemaining, err
}

// Removes a shape from the canvas.
// Can return the following errors:
// - DisconnectedError
// - ShapeOwnerError
func (c *MyCanvas) DeleteShape(validateNum uint8, shapeHash string) (inkRemaining uint32, err error) {
	args := DelShapeArgs{validateNum, shapeHash, c.artnodePrivKey}
	fmt.Print(args.ShapeHash, "lib!!!")
	err = c.conn.Call("InkMinerRPC.DeleteShape", args, &inkRemaining)
	return inkRemaining, err
}

// Retrieves hashes contained by a specific block.
// Can return the following errors:
// - DisconnectedError
// - InvalidBlockHashError
func (c *MyCanvas) GetShapes(blockHash string) (shapeHashes []string, err error) {
	err = c.conn.Call("InkMinerRPC.GetShapes", blockHash, &shapeHashes)
	return shapeHashes, err
}

// Returns the block hash of the genesis block.
// Can return the following errors:
// - DisconnectedError
func (c *MyCanvas) GetGenesisBlock() (blockHash string, err error) {
	arg := 0
	err = c.conn.Call("InkMinerRPC.GetGenesisBlock", arg, &blockHash)
	return blockHash, err
}

// Retrieves the children blocks of the block identified by blockHash.
// Can return the following errors:
// - DisconnectedError
// - InvalidBlockHashError
func (c *MyCanvas) GetChildren(blockHash string) (blockHashes []string, err error) {

	err = c.conn.Call("InkMinerRPC.GetChildren", blockHash, &blockHashes)
	return blockHashes, err
}

// Closes the canvas/connection to the BlockArt network.
// - DisconnectedError
func (c *MyCanvas) CloseCanvas() (inkRemaining uint32, err error) {
	args := 0
	// tmp := make(map[string][]string)

	var reply *CloseCanvReply
	reply = &CloseCanvReply{}
	// reply.canvOps = &tmp
	err = c.conn.Call("InkMinerRPC.CloseCanvas", args, &reply)
	ops := (*reply).CanvOps
	//fmt.Println("CC:", *reply)
	tmpMap := make(map[string]string)
	height := fmt.Sprint(c.CanvSetting.CanvasYMax)
	width := fmt.Sprint(c.CanvSetting.CanvasXMax)
	html := "<!DOCTYPE html PUBLIC \"-//IETF//DTD HTML 2.0//EN\"> <HTML><HEAD></HEAD><BODY>	<svg xmlns=\"http://www.w3.org/2000/svg\" version=\"1.1\" height=\""
	html += height
	html += "\" width=\""
	html += width + "\">"
	for _, elem := range ops {
		for k := 0; k < len(elem); k++ {
			strs := strings.Split(elem[k], ":")
			svgString := strs[0]
			shapehash := strs[1]
			if svgString != "delete" {
				tmpMap[shapehash] = svgString
			} else if svgString == "delete" {
				delete(tmpMap, shapehash)
			}
		}
	}

	for _, val := range tmpMap {
		html = html + val
	}
	html = html + "</svg> </BODY> </HTML>"

	d1 := []byte(html)
	saveOnDisk(d1)
	// fmt.Println("8787872359874====++", html)
	inkRemaining = (*reply).InkRemaining
	return inkRemaining, err
}

//======================================================================
//helper functions
//======================================================================
func saveOnDisk(data []byte) error {
	// @ fail error
	// fmt.Println("ddd+++++++++++++++++++++++++++++++++", data)
	file := "./drawOutput.html"
	fout, err2 := os.Create(file)
	if err2 != nil {
		fmt.Println(file, err2)
	}
	defer fout.Close()
	if len(data) != 0 {
		fout.Write(data)
	}
	return nil
}

func exitOnError(prefix string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s, err = %s\n", prefix, err.Error())
		os.Exit(1)
	}
}

func getPrivKeyInStr(privKey ecdsa.PrivateKey) string {
	privateKeyBytes, _ := x509.MarshalECPrivateKey(&privKey)
	privKeyInString := hex.EncodeToString(privateKeyBytes)
	return privKeyInString
}

func validSvgCommand(c string) error {

	for i := 0; i < len(c); i++ {
		var s = string(c[i : i+1])
		matched, _ := regexp.MatchString(" |M|m|L|l|H|h|V|v|Z|z|[0-9]+", s)
		if !matched {
			return InvalidShapeSvgStringError(c)
		}
		// fmt.Println(matched, s)
	}

	return nil
}
