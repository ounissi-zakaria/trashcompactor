package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/michael1026/sessionManager"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/projectdiscovery/fastdialer/fastdialer"
)

var (
	urlMap      cmap.ConcurrentMap[string, bool]
	jsonResults cmap.ConcurrentMap[string, string]
	client      *http.Client
	threads     int
)

type CookieInfo map[string]string

type Response struct {
	*http.Response
	url string
	err error
}

type Request struct {
	*http.Request
	url string
}

func AddAndPrintIfUnique(urlMap cmap.ConcurrentMap[string, bool], key string, url string, contentType string) {
	if _, ok := urlMap.Get(key); !ok {
		fmt.Println(url)
		urlMap.Set(key, true)
		jsonResults.Set(url, contentType)
	}
}

func buildHttpClient(jar *cookiejar.Jar) (c *http.Client) {
	fastdialerOpts := fastdialer.DefaultOptions
	fastdialerOpts.EnableFallback = true
	dialer, err := fastdialer.NewDialer(fastdialerOpts)
	if err != nil {
		log.Fatal("Error building HTTP client")
		return nil
	}

	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		MaxConnsPerHost:     100,
		IdleConnTimeout:     time.Second * 10,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			Renegotiation:      tls.RenegotiateOnceAsClient,
		},
		DisableKeepAlives: false,
		DialContext:       dialer.Dial,
	}

	re := func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return http.ErrUseLastResponse
		}
		return nil
	}

	client := &http.Client{
		Transport:     transport,
		CheckRedirect: re,
		Timeout:       time.Second * 5,
		Jar:           jar,
	}

	return client
}

func main() {
	urlMap = cmap.New[bool]()
	cookieFile := flag.String("C", "", "File containing cookie")
	flag.IntVar(&threads, "t", 5, "Number of concurrent threads")
	outputJson := flag.String("json", "", "Output as json")
	jsonResults = cmap.New[string]()

	flag.Parse()

	jar := sessionManager.ReadCookieJson(*cookieFile)
	urls := []string{}

	client = buildHttpClient(jar)

	s := bufio.NewScanner(os.Stdin)

	for s.Scan() {
		urls = append(urls, s.Text())
	}

	reqChan := make(chan Request)
	var wg sync.WaitGroup

	go producer(urls, reqChan)
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go consumer(reqChan, &wg)
	}
	wg.Wait()

	if *outputJson != "" {
		jsonFile, err := json.Marshal(jsonResults)

		if err != nil {
			fmt.Printf("Error marshalling JSON: %s\n", err)
			return
		}

		err = ioutil.WriteFile(*outputJson, jsonFile, 0644)

		if err != nil {
			fmt.Printf("Error writing JSON to file: %s\n", err)
		}
	}
}

func printUniqueContentURLs(resp http.Response, rawUrl string) {
	if resp.StatusCode == http.StatusOK {
		defer resp.Body.Close()
		contentType := resp.Header.Get("content-type")
		resource := ""

		if contentType == "" || strings.HasPrefix(contentType, "text/html") {
			doc, err := goquery.NewDocumentFromReader(resp.Body)

			if err != nil {
				return
			}

			doc.Find("script[src]").Each(func(index int, item *goquery.Selection) {
				src, _ := item.Attr("src")
				srcurl, err := url.Parse(src)

				if err != nil {
					return
				}

				srcurl.RawQuery = ""

				resource += srcurl.String()
			})

			AddAndPrintIfUnique(urlMap, resource, rawUrl, "text/html")
		} else if strings.HasPrefix(contentType, "application/json") {
			var resultMap map[string]interface{}
			body, err := ioutil.ReadAll(resp.Body)

			if err != nil {
				return
			}

			err = json.Unmarshal([]byte(body), &resultMap)

			if err != nil {
				return
			}

			resource = mapKeysToString(resultMap)

			AddAndPrintIfUnique(urlMap, resource, rawUrl, "application/json")
		}
	}
}

func mapKeysToString(jsonMap map[string]interface{}) string {
	finalString := ""
	for k := range jsonMap {
		finalString += k
	}
	return finalString
}

func producer(urls []string, reqChan chan Request) {
	defer close(reqChan)
	for _, url := range urls {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		req.Close = true
		req.Header.Add("Connection", "close")
		req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
		req.Header.Add("Accept-Language", "en-US,en;q=0.9")
		req.Header.Add("Priority", "u=0, i")
		req.Header.Add("Sec-Ch-Ua", "\"Chromium\";v=\"148\", \"Brave\";v=\"148\", \"Not/A)Brand\";v=\"99\"")
		req.Header.Add("Sec-Ch-Ua-Mobile", "?0")
		req.Header.Add("Sec-Ch-Ua-Platform", "\"Linux\"")
		req.Header.Add("Sec-Fetch-Dest", "document")
		req.Header.Add("Sec-Fetch-Mode", "navigate")
		req.Header.Add("Sec-Fetch-Site", "none")
		req.Header.Add("Sec-Fetch-User", "?1")
		req.Header.Add("Sec-Gpc", "1")
		req.Header.Add("Upgrade-Insecure-Requests", "1")
		req.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36")

		reqChan <- Request{req, url}
	}

}

func consumer(reqChan chan Request, wg *sync.WaitGroup) {
	defer wg.Done()
	for req := range reqChan {
		if req.Request != nil {
			resp, err := client.Do(req.Request)
			r := Response{resp, req.url, err}
			if r.Response != nil {
				printUniqueContentURLs(*r.Response, r.url)
			}
		}
	}
}
