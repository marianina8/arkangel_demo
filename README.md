# ArkAngel demo
This `arkangel_demo` package uses PicPurify 3rd Party API to run porn/gore/drug detection on a video file, blurring out any inappropriate content.


## Installing

Before you begin, you'll of course need the Go programming language installed.

Install:
[GoCV](https://gocv.io/)

Gain access to a [PicPurify](https://www.picpurify.com/) API Key available only through a paid account.

Export `picpurify_key`:

`export picpurify_key={API Key}`

1. Clone this repo.
2. Run `dep ensure`
3. Build the application with `go build`.
5. Run the program according the usage below.

## Usage

`arkangel_demo -fps={frames per second of video file} -video={filepath of video file}`

Both parameters, fps and video are required.

## Demo

View the code running on a snippet of a Cannabis 101 video: https://www.youtube.com/watch?v=KEccdkAznvU
PicPurify performs well, but does not detect small buds and wax.


## Future To Do

-[ ] Create output (string) file parameter that will output a new video with impure content blurred.
