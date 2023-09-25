package main

import (
	"HaeProxy/module/finger"
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/PuerkitoBio/goquery"
	"github.com/gookit/color"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type Outrestul struct {
	Url        string `json:"url"`
	Cms        string `json:"cms"`
	Server     string `json:"server"`
	Statuscode int    `json:"statuscode"`
	Length     int    `json:"length"`
	Title      string `json:"title"`
}

type Data struct {
	Request  string `json:"request"`
	Response string `json:"response"`
	//Url      string `json:"url"`
}

func NewScan() *finger.Packjson {

	err := finger.LoadWebfingerprint("./" + "/finger.json")
	//err := finger.LoadWebfingerprint("/Users/callc/tools/InformationGathering/EHole-main/finger.json")
	if err != nil {
		color.RGBStyleFromString("237,64,35").Println("[error] fingerprint file error!!!")
		os.Exit(1)
	}
	var packjson *finger.Packjson
	packjson = finger.GetWebfingerprint()
	//for _, url := range urls {
	//	s.UrlQueue.Push([]string{url, "0"})
	//}
	return packjson
}

func main() {
	// 监听本地的 8080 端口
	listener, err := net.Listen("tcp", "127.0.0.1:19090")
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		return
	}
	defer listener.Close()

	fmt.Println("Listening on 127.0.0.1:19090")

	for {
		// 接收连接
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting:", err.Error())
			continue
		}

		// 处理连接
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// 读取数据
	buf := make([]byte, 0)
	tmp := make([]byte, 1024)
	for {
		n, err := conn.Read(tmp)
		if err != nil {
			if err == io.EOF {
				break
			}
			fmt.Println("Error reading:", err.Error())
			return
		}
		buf = append(buf, tmp[:n]...)
		if n < 1024 {
			break
		}
	}

	// 输出数据
	//fmt.Println(string(buf))

	jsonStr := string(buf)
	// 将 JSON 字符串解析为 Go 数据结构

	var data Data
	err := json.Unmarshal([]byte(jsonStr), &data)
	if err != nil {
		panic(err)
	}

	BurpResponse, err := url.QueryUnescape(data.Response)
	if err != nil {
		panic(err)
	}

	//BurpUrl, err := url.QueryUnescape(data.Url)
	//if err != nil {
	//	panic(err)
	//}

	BurpRequest, err := url.QueryUnescape(data.Request)
	if err != nil {
		panic(err)
	}

	//fmt.Printf("Response: %s, Url: %s\n", BurpResponse, BurpUrl)

	// 将响应包字符串转换为 http.Request 对象
	reaq, err := http.ReadRequest(bufio.NewReader(bytes.NewBufferString(BurpRequest)))
	if err != nil {
		panic(err)
	}

	// 将响应包字符串转换为 http.Response 对象
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewBufferString(BurpResponse)), nil)
	if err != nil {
		panic(err)
	}

	headers := MapToJson(resp.Header)
	fingerprints := NewScan()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	title := gettitle(BurpResponse)
	favhash := ""
	//fmt.Println(fingerprints)

	path := reaq.RequestURI
	if strings.Contains(path, string('?')) {
		path = strings.Split(path, "?")[0]
	}
	lastDotIndex := strings.LastIndex(path, ".")
	if lastDotIndex != -1 {
		suffix := strings.ToLower(path[lastDotIndex+1:])
		suffix2 := "3g2|3gp|7z|aac|abw|aif|aifc|aiff|arc|au|avi|azw|bin|bmp|bz|bz2|cmx|cod|csh|css|csv|doc|docx|eot|epub|gif|gz|ics|ief|jar|jfif|jpe|jpeg|jpg|m3u|mid|midi|mjs|mp2|mp3|mpa|mpe|mpeg|mpg|mpkg|mpp|mpv2|odp|ods|odt|oga|ogv|ogx|otf|pbm|pdf|pgm|png|pnm|ppm|ppt|pptx|ra|ram|rar|ras|rgb|rmi|rtf|snd|svg|swf|tar|tif|tiff|ttf|vsd|wav|weba|webm|webp|woff|woff2|xbm|xls|xlsx|xpm|xul|xwd|zip|zip"

		extensions := strings.Split(suffix2, "|")

		for _, ext := range extensions {
			if strings.Contains(suffix, ext) {
				return
			}
		}

		///计算有点问题，可能是数据传输过程中有问题，咱叔放弃
		//if suffix == "ico" {
		//
		//	favhash = finger.Mmh3Hash32(finger.StandBase64(body))
		//
		//} else {
		//
		//	favhash = ""
		//
		//}

	}

	var cms []string
	for _, finp := range fingerprints.Fingerprint {
		if finp.Location == "body" {
			if finp.Method == "keyword" {

				if finger.Iskeyword(string(body), finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
			if finp.Method == "faviconhash" {
				if favhash == finp.Keyword[0] {
					cms = append(cms, finp.Cms)
				}
			}
			if finp.Method == "regular" {
				if finger.Isregular(string(body), finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
		}

		if finp.Location == "header" {
			if finp.Method == "keyword" {
				if finger.Iskeyword(headers, finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
			if finp.Method == "regular" {
				if finger.Isregular(headers, finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
		}

		if finp.Location == "title" {
			if finp.Method == "keyword" {
				if finger.Iskeyword(title, finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
			if finp.Method == "regular" {
				if finger.Isregular(title, finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
		}
	}

	if len(cms) > 0 {
		cmss := strings.Join(cms, ",")
		outstr := fmt.Sprintf("[ %s | %s ]", reaq.Host, cmss)
		color.RGBStyleFromString("237,64,35").Println(outstr)
	}
	//fmt.Println(NewScan())

	//fmt.Println(headers)

	//fmt.Println(reaq.RequestURI)
	//fmt.Println(reaq.URL)
	//fmt.Println(reaq.Host)

	// 输出 http.Response 对象的状态码和响应体
	//fmt.Println(resp.StatusCode)
	//body, err := ioutil.ReadAll(resp.Body)
	//if err != nil {
	//	panic(err)
	//}
	//fmt.Println(string(body))

}

func MapToJson(param map[string][]string) string {
	dataType, _ := json.Marshal(param)
	dataString := string(dataType)
	return dataString
}

func gettitle(httpbody string) string {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(httpbody))
	if err != nil {
		return "Not found"
	}
	title := doc.Find("title").Text()
	title = strings.Replace(title, "\n", "", -1)
	title = strings.Trim(title, " ")
	return title
}
