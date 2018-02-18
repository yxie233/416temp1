/*

This test utilizes most of the blockartlib API (excluding delete shape)
to verify that the API is functional.

1. Add a parallelogram, and obtain its shape hash and the block hash the operation is
stored in. Expect that this shape costs 2500 ink to draw.
2. Next, obtain all the shapes of the block given by the block hash in step #1 and verify
that it is the same shape hash as was returned in step #1.
3-4. Verify that we can obtain the genesis block hash and obtain a list of child nodes.
5. Next, we verify that, given the shape hash in step #1, we can obtain back the same SVG string
that we fed into the API call in step #1.
6. Finally, we invoke blockartlib.GetSvgString with gibberish hash and verify that we obtain
an invalid shape hash error.


Usage:
go run art-app.go <miner-addr:art-app-port> <privKey>
*/

package main

// Expects blockartlib.go to be in the ./blockartlib/ dir, relative to
// this art-app.go file
import (
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"

	"../blockartlib"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Server address [ip:port] privatekeyString")
		return
	}
	minerAddr := os.Args[1]
	privString := os.Args[2]
	privateKeyBytesRestored, _ := hex.DecodeString(privString)
	privKey, _ := x509.ParseECPrivateKey(privateKeyBytesRestored)

	// Open a canvas.
	// canvas, settings, err := blockartlib.OpenCanvas(minerAddr, *privKey)
	canvas, _, err := blockartlib.OpenCanvas(minerAddr, *privKey)
	if checkError(err) != nil {
		fmt.Println(err)
		return
	}

	validateNum := uint8(2)
	//fmt.Print(canvas, "ignore", validateNum)

	/************************
	Add a parallelogram
	*************************/
	shapeHash, blockHash, _, err := canvas.AddShape(validateNum, blockartlib.PATH, "M 600 0 l 50 0 l 50 50 h -50 z", "transparent", "red")
	if checkError(err) != nil {
		return
	}
	fmt.Println("----------------------------")
	fmt.Printf("Shape hash: %s, block hash: %s\n", shapeHash, blockHash)
	fmt.Println("----------------------------")

	blockShapes, err := canvas.GetShapes(blockHash)
	if checkError(err) != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("----------------------------")
	fmt.Println("block shapes")
	fmt.Println(blockShapes)
	fmt.Println("----------------------------")

	genHash, err := canvas.GetGenesisBlock()
	if checkError(err) != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("----------------------------")
	fmt.Printf("gen hash %s\n", genHash)
	fmt.Println("----------------------------")

	childrenBlocks, err := canvas.GetChildren(genHash)
	if checkError(err) != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("----------------------------")
	fmt.Println("children blocks of gen block")
	fmt.Println(childrenBlocks)
	fmt.Println("----------------------------")

	svgString, err := canvas.GetSvgString(shapeHash)
	if checkError(err) != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("----------------------------")
	fmt.Printf("actual svg string: %s\n", svgString)
	fmt.Printf("expected svg string: %s\n", "M 500 0 l 50 0 l 50 50 h -50 z")
	fmt.Println("----------------------------")

	_, err = canvas.GetSvgString("gibberish")
	fmt.Println("----------------------------")
	fmt.Println("Error expected below: v")
	checkError(err)
	fmt.Println("----------------------------")

	// Close the canvas.
	ink4, err := canvas.CloseCanvas()
	if checkError(err) != nil {
		return
	}
	fmt.Println(ink4)
}

// If error is non-nil, print it out and return it.
func checkError(err error) error {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error ", err.Error())
		return err
	}
	return nil
}
