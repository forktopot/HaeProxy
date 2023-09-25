package main

import (
	"HaeProxy/module/finger"
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/PuerkitoBio/goquery"
	"github.com/gookit/color"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type Data struct {
	Request  string `json:"request"`
	Response string `json:"response"`
	//Url      string `json:"url"`
}

func NewScan() *finger.Config {

	err := finger.LoadWebfingerprint("./" + "/finger.json")
	if err != nil {
		color.RGBStyleFromString("237,64,35").Println("[error] fingerprint file error!!!")
		os.Exit(1)
	}
	var config *finger.Config
	config = finger.GetWebfingerprint()
	//for _, url := range urls {
	//	s.UrlQueue.Push([]string{url, "0"})
	//}
	return config
}

func main() {
	// 定义命令行参数变量
	ip := flag.String("ip", "127.0.0.1", "IP 地址")
	port := flag.Int("port", 18989, "端口号")

	// 解析命令行参数
	flag.Parse()
	address := net.JoinHostPort(*ip, strconv.Itoa(*port))
	fmt.Println(address)
	// 监听本地的 8080 端口
	listener, err := net.Listen("tcp", address)
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		return
	}
	defer listener.Close()

	fmt.Sprintf("Listening on %s:%d", ip, port)

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

	fingerprints := NewScan()

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

	// 替换掉 BurpResponse 中的 HTTP 版本号为有效的版本号
	validResponse := strings.Replace(BurpResponse, "HTTP/2", "HTTP/1.1", 1)
	// 将响应包字符串转换为 http.Response 对象
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewBufferString(validResponse)), nil)
	if err != nil {
		panic(err)
	}

	respheaders := MapToJson(resp.Header)
	reapheaders := MapToJson(reaq.Header)
	respbody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	reaqbody, err := ioutil.ReadAll(reaq.Body)
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

				if finger.Iskeyword(string(respbody), finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
			if finp.Method == "faviconhash" {
				if favhash == finp.Keyword[0] {
					cms = append(cms, finp.Cms)
				}
			}
			if finp.Method == "regular" {
				if finger.Isregular(string(respbody), finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
		}

		if finp.Location == "header" {
			if finp.Method == "keyword" {
				if finger.Iskeyword(respheaders, finp.Keyword) {
					cms = append(cms, finp.Cms)
				}
			}
			if finp.Method == "regular" {
				if finger.Isregular(respheaders, finp.Keyword) {
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

	var information []string
	var information2 []string
	var information3 []string

	for _, finp := range fingerprints.Information {
		if finp.Scope == "request" {
			if finp.Location == "body" {
				information = append(information, finger.Isregular2(string(reaqbody), finp.Keyword)...)
				if len(information) > 0 {
					information2 = append(information2, finp.Name)
					information2 = append(information2, ":")
					information2 = append(information2, strings.ReplaceAll(strings.Join(information, " "), "\n", ""))
					information2 = append(information2, " | ")
					//information2 = append(information2, " | ")
				}
				information = information[:0]
			}
			if finp.Location == "header" {
				information = append(information, finger.Isregular2(reapheaders, finp.Keyword)...)
				if len(information) > 0 {
					information2 = append(information2, finp.Name)
					information2 = append(information2, ":")
					information2 = append(information2, strings.ReplaceAll(strings.Join(information, " "), "\n", ""))
					information2 = append(information2, " | ")
				}
				information = information[:0]
			}
			if finp.Location == "any" {
				information = append(information, finger.Isregular2(BurpRequest, finp.Keyword)...)
				if len(information) > 0 {
					information2 = append(information2, finp.Name)
					information2 = append(information2, ":")
					information2 = append(information2, strings.ReplaceAll(strings.Join(information, " "), "\n", ""))
					information2 = append(information2, " | ")
				}
				information = information[:0]
			}
		}
		if finp.Scope == "response" {
			if finp.Location == "body" {
				information = append(information, finger.Isregular2(string(respbody), finp.Keyword)...)
				if len(information) > 0 {
					information2 = append(information2, finp.Name)
					information2 = append(information2, ":")
					information2 = append(information2, strings.ReplaceAll(strings.Join(information, " "), "\n", ""))
					information2 = append(information2, " | ")
				}
				information = information[:0]
			}
			if finp.Location == "header" {
				information = append(information, finger.Isregular2(respheaders, finp.Keyword)...)
				if len(information) > 0 {
					information2 = append(information2, finp.Name)
					information2 = append(information2, ":")
					information2 = append(information2, strings.ReplaceAll(strings.Join(information, " "), "\n", ""))
					information2 = append(information2, " | ")
				}
				information = information[:0]
			}
			if finp.Location == "any" {
				information = append(information, finger.Isregular2(BurpResponse, finp.Keyword)...)
				if len(information) > 0 {
					information2 = append(information2, finp.Name)
					information2 = append(information2, ":")
					information2 = append(information2, strings.ReplaceAll(strings.Join(information, " "), "\n", ""))
					information2 = append(information2, " | ")
				}
				information = information[:0]
			}
		}
		if finp.Scope == "any" {
			if finp.Location == "body" {
				information = append(information, finger.Isregular2(string(reaqbody), finp.Keyword)...)
				if len(information) > 0 {
					information2 = append(information2, finp.Name)
					information2 = append(information2, ":")
					information2 = append(information2, strings.ReplaceAll(strings.Join(information, " "), "\n", ""))
					information2 = append(information2, " | ")
				}
				information = information[:0]
				information = append(information, finger.Isregular2(string(respbody), finp.Keyword)...)
				if len(information) > 0 {
					information2 = append(information2, finp.Name)
					information2 = append(information2, ":")
					information2 = append(information2, strings.ReplaceAll(strings.Join(information, " "), "\n", ""))
					information2 = append(information2, " | ")
				}
				information = information[:0]
			}
			if finp.Location == "header" {
				information = append(information, finger.Isregular2(reapheaders, finp.Keyword)...)
				if len(information) > 0 {
					information2 = append(information2, finp.Name)
					information2 = append(information2, ":")
					information2 = append(information2, strings.ReplaceAll(strings.Join(information, " "), "\n", ""))
					information2 = append(information2, " | ")
				}
				information = information[:0]
				information = append(information, finger.Isregular2(respheaders, finp.Keyword)...)
				if len(information) > 0 {
					information2 = append(information2, finp.Name)
					information2 = append(information2, ":")
					information2 = append(information2, strings.ReplaceAll(strings.Join(information, " "), "\n", ""))
					information2 = append(information2, " | ")
				}
				information = information[:0]
			}
			if finp.Location == "any" {
				information = append(information, finger.Isregular2(BurpResponse, finp.Keyword)...)
				if len(information) > 0 {
					information2 = append(information2, finp.Name)
					information2 = append(information2, ":")
					information2 = append(information2, strings.ReplaceAll(strings.Join(information, " "), "\n", ""))
					information2 = append(information2, " | ")
				}
				information = information[:0]
				information = append(information, finger.Isregular2(BurpRequest, finp.Keyword)...)
				if len(information) > 0 {
					information2 = append(information2, finp.Name)
					information2 = append(information2, ":")
					information2 = append(information2, strings.ReplaceAll(strings.Join(information, " "), "\n", ""))
					information2 = append(information2, " | ")
				}
				information = information[:0]
			}
		}
		if len(information2) > 0 {
			information3 = append(information3, strings.Join(information2, " "))
			information2 = information2[:0]
		}
	}

	if len(information3) > 0 {
		informations := strings.Join(information3, " ")
		outstr := fmt.Sprintf("[ %s | %s ]", reaq.Host+reaq.RequestURI, informations)
		color.RGBStyleFromString("0,255,0").Println(outstr)
	}

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
