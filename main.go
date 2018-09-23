package main

import (
	"flag"
	"fmt"
	"image"
	"os"
	"runtime"

	"github.com/marianina8/arkangel_demo/picpurify"
	"gocv.io/x/gocv"
)

const (
	threshold = 0.80
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	runtime.LockOSThread()
	video := flag.String("video", "", "video to be analyzed for impure content")
	fps := flag.Int("fps", 0, "frames per second")
	flag.Parse()
	if *video == "" || *fps == 0 {
		flag.Usage()
		return
	}
	key := os.Getenv("picpurify_key")
	picPurify, err := picpurify.NewClient(key)
	check(err)
	videoData, err := picPurify.DetectImpurityVideo(*video)
	check(err)
	displayVideo(*fps, videoData, *video)
}

func displayVideo(fps int, videoData picpurify.VideoData, filename string) {
	var blur bool
	stream, err := gocv.VideoCaptureFile(filename)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer stream.Close()

	// open display window
	window := gocv.NewWindow("Arkangel Demo")
	defer window.Close()

	// prepare image matrix
	img := gocv.NewMat()
	defer img.Close()
	framenum := 0
	for {
		if ok := stream.Read(&img); !ok {
			framenum++
			continue
		}
		if img.Empty() {
			framenum++
			continue
		}
		if framenum%fps == 0 {
			seconds := framenum / fps
			if len(videoData.ImagesResults) <= seconds {
				break
			}
			if videoData.ImagesResults[seconds].PornDetection.PornContent && videoData.ImagesResults[seconds].PornDetection.ConfidenceScore > threshold {
				fmt.Println("BLUR! Porn detected!")
				blur = true
			} else if videoData.ImagesResults[seconds].GoreDetection.GoreContent && videoData.ImagesResults[seconds].GoreDetection.ConfidenceScore > threshold {
				fmt.Println("BLUR! Gore detected!")
				blur = true
			} else if videoData.ImagesResults[seconds].DrugDetection.DrugContent && videoData.ImagesResults[seconds].DrugDetection.ConfidenceScore > threshold {
				fmt.Println("BLUR! Drugs detected!")
				blur = true
			} else {
				fmt.Println("Clean - OK!")
				blur = false
			}
		}

		if blur {
			gocv.GaussianBlur(img, &img, image.Pt(75, 75), 0, 0, gocv.BorderDefault)
		}

		// show the image in the window, and wait 1 millisecond
		window.IMShow(img)
		if window.WaitKey(1) >= 0 {
			break
		}
		framenum++
	}
}
