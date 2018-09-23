package picpurify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"os"
	"time"

	"github.com/pkg/errors"
)

const (
	defaultImageURL = "https://www.picpurify.com/analyse.php"
	defaultVideoURL = "https://www.picpurify.com/analyse_video.php"
)

// VideoData holds all picpurify result for video files
type VideoData struct {
	TaskCall                string  `json:"task_call"`
	NbImages                int     `json:"nb_images"`
	FinalDecision           string  `json:"final_decision"`
	ConfidenceScoreDecision float64 `json:"confidence_score_decision"`
	NbImagesOk              int     `json:"nb_images_ok"`
	NbImagesKo              int     `json:"nb_images_ko"`
	Media                   struct {
		URLVideo    string `json:"url_video"`
		FileVideo   string `json:"file_video"`
		MediaID     string `json:"media_id"`
		ReferenceID string `json:"reference_id"`
		OriginID    string `json:"origin_id"`
	} `json:"media"`
	TotalComputeTime float64 `json:"total_compute_time"`
	ImagesResults    []struct {
		Status        string `json:"status"`
		PornDetection struct {
			ConfidenceScore float64 `json:"confidence_score"`
			ComputeTime     float64 `json:"compute_time"`
			PornContent     bool    `json:"porn_content"`
		} `json:"porn_detection"`
		ConfidenceScoreDecision float64 `json:"confidence_score_decision"`
		GoreDetection           struct {
			GoreContent     bool    `json:"gore_content"`
			ComputeTime     float64 `json:"compute_time"`
			ConfidenceScore float64 `json:"confidence_score"`
		} `json:"gore_detection"`
		DrugDetection struct {
			DrugContent     bool    `json:"drug_content"`
			ComputeTime     float64 `json:"compute_time"`
			ConfidenceScore float64 `json:"confidence_score"`
		} `json:"drug_detection"`
		TaskCall       string        `json:"task_call"`
		RejectCriteria []interface{} `json:"reject_criteria"`
		Performed      []string      `json:"performed"`
		SubCalls       []string      `json:"sub_calls"`
		FinalDecision  string        `json:"final_decision"`
		Media          struct {
			URLImage    string `json:"url_image"`
			FileImage   string `json:"file_image"`
			MediaID     string `json:"media_id"`
			ReferenceID string `json:"reference_id"`
			OriginID    string `json:"origin_id"`
		} `json:"media"`
		TotalComputeTime float64 `json:"total_compute_time"`
	} `json:"images_results"`
}

// ImageData holds all picpurify result for image files
type ImageData struct {
	Status                  string  `json:"status"`
	FinalDecision           string  `json:"final_decision"`
	ConfidenceScoreDecision float64 `json:"confidence_score_decision"`
	PornDetection           struct {
		ConfidenceScore float64 `json:"confidence_score"`
		ComputeTime     float64 `json:"compute_time"`
		PornContent     bool    `json:"porn_content"`
	} `json:"porn_detection"`
	DrugDetection struct {
		DrugContent     bool    `json:"drug_content"`
		ComputeTime     float64 `json:"compute_time"`
		ConfidenceScore float64 `json:"confidence_score"`
	} `json:"drug_detection"`
	GoreDetection struct {
		GoreContent     bool    `json:"gore_content"`
		ComputeTime     float64 `json:"compute_time"`
		ConfidenceScore float64 `json:"confidence_score"`
	} `json:"gore_detection"`
	TaskCall       string        `json:"task_call"`
	RejectCriteria []interface{} `json:"reject_criteria"`
	Performed      []string      `json:"performed"`
	SubCalls       []string      `json:"sub_calls"`
	Media          struct {
		URLImage    string `json:"url_image"`
		FileImage   string `json:"file_image"`
		MediaID     string `json:"media_id"`
		OriginID    string `json:"origin_id"`
		ReferenceID string `json:"reference_id"`
	} `json:"media"`
	TotalComputeTime float64 `json:"total_compute_time"`
}

// Client for PicPurify
type Client struct {
	Client *http.Client

	Tasks    string
	ImageURL string
	VideoURL string
	Key      string
}

// NewClient creates a new client for PicPurify
func NewClient(key string) (*Client, error) {
	if key == "" {
		return nil, errors.New("missing picpurify_key")
	}
	c := Client{}
	c.Client = &http.Client{
		Timeout: 240 * time.Second,
	}
	c.Tasks = "porn_detection,gore_detection,drug_detection"
	c.ImageURL = defaultImageURL
	c.VideoURL = defaultVideoURL
	c.Key = key
	return &c, nil
}

// DetectImpurityVideo detects any impurity in a video
func (c *Client) DetectImpurityVideo(filename string) (VideoData, error) {
	data := VideoData{}
	f, err := os.Open(filename)
	if err != nil {
		return data, err
	}
	r, err := ioutil.ReadAll(f)
	if err != nil {
		return data, err
	}
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	defer w.Close()

	fw, err := w.CreateFormFile("file_video", filename)
	if err != nil {
		return data, err
	}
	if _, err = fw.Write(r); err != nil {
		return data, err
	}

	fw, err = w.CreateFormField("API_KEY")
	if err != nil {
		return data, err
	}
	if _, err = fw.Write([]byte(c.Key)); err != nil {
		return data, err
	}

	if fw, err = w.CreateFormField("task"); err != nil {
		return data, err
	}
	if _, err = fw.Write([]byte(c.Tasks)); err != nil {
		return data, err
	}
	req, err := http.NewRequest(http.MethodPost, c.VideoURL, &b)
	if err != nil {
		return data, errors.Wrap(err, "picpurify client: creating request")
	}
	req.ContentLength = int64(len(b.Bytes()))
	req.Header.Set("Content-Type", w.FormDataContentType())
	fmt.Println("content length! ", req.ContentLength)
	var bytes []byte
	resp, err := c.Client.Do(req)
	if err != nil {
		return data, errors.Wrap(err, "picpurify client: executing request")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return data, errors.Errorf("got unexpected http code: %d", resp.StatusCode)
	}

	bytes, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return data, errors.Wrap(err, "picpurify client: reading response body")
	}

	if err != nil {
		return data, errors.New("retrieving data from picpurify")
	}
	fmt.Println(string(bytes))
	err = json.Unmarshal(bytes, &data)
	return data, err
}

// DetectImpurityImage detects any impurity in an image
func (c *Client) DetectImpurityImage(r io.Reader) (ImageData, error) {
	data := ImageData{}
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	defer w.Close()

	fw, err := w.CreateFormFile("file_image", "picpurify")
	if err != nil {
		return data, err
	}
	if _, err = io.Copy(fw, r); err != nil {
		return data, err
	}

	fw, err = w.CreateFormField("API_KEY")
	if err != nil {
		return data, err
	}
	if _, err = fw.Write([]byte(c.Key)); err != nil {
		return data, err
	}

	if fw, err = w.CreateFormField("task"); err != nil {
		return data, err
	}
	if _, err = fw.Write([]byte(c.Tasks)); err != nil {
		return data, err
	}

	req, err := http.NewRequest(http.MethodPost, c.ImageURL, &b)
	if err != nil {
		return data, errors.Wrap(err, "picpurify client: creating request")
	}
	req.ContentLength = int64(len(b.Bytes()))
	req.Header.Set("Content-Type", w.FormDataContentType())

	var bytes []byte
	resp, err := c.Client.Do(req)
	if err != nil {
		return data, errors.Wrap(err, "picpurify client: executing request")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return data, errors.Errorf("got unexpected http code: %d", resp.StatusCode)
	}

	bytes, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return data, errors.Wrap(err, "picpurify client: reading response body")
	}

	if err != nil {
		return data, errors.New("retrieving data from picpurify")
	}
	err = json.Unmarshal(bytes, &data)
	return data, err
}
