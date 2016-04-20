package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/tls"
    "encoding/base64"
    "io"
    "io/ioutil"
    "flag"
    "fmt"
    "golang.org/x/crypto/ssh/terminal"
    "golang.org/x/net/html"
    "log"
    "net/http"
    "net/url"
    "os"
    "sync"
    "syscall"
    "strings"
    "time"
)

type (
    HttpUrls struct {
        HttpClient *http.Client

        SecretKey []byte

        Username string
        ReadPassword bool
        Password string

        Urls []string

        FileName string

        Debug bool
    }

    HttpUrl struct {
        HttpUrls *HttpUrls
        Url string
    }
)

func main() {
    httpUrls, err := NewHttpUrls()
    if err != nil {
        log.Fatal(err)
    }
    httpUrls.Ls()
}

func (this *HttpUrls) Ls() {
    for fileName := range this.FileNames() {
        fmt.Println(fileName)
    }
}

func (this *HttpUrls) FileNames() <-chan string {
    fileNames := make(chan string, 64)

    go func() {
        var wg sync.WaitGroup

        defer close(fileNames)
        defer wg.Wait()

        wg.Add(len(this.Urls))
        for _, url := range this.Urls {
            go func(url string) {
                defer wg.Done()
                NewHttpUrl(this, url).Ls(fileNames)
            }(url)
        }
    }()

    return fileNames
}

func NewHttpUrls() (*HttpUrls, error) {
    httpUrls := &HttpUrls{
        HttpClient: &http.Client{
            Transport: &http.Transport{
                TLSClientConfig: &tls.Config{
                    InsecureSkipVerify: true,
                },
            },
            Timeout: time.Duration(3 * time.Second),
        },
        SecretKey: make([]byte, 32),
    }

    if _, err := rand.Read(httpUrls.SecretKey); err != nil {
        return nil, err
    }

    name, sep := os.Args[0], "/"
    idx := strings.LastIndex(name, sep)
    if idx != -1 {
        name = name[idx + len(sep):]
    }

    flagSet := flag.NewFlagSet(name, flag.ContinueOnError)
    flagSet.StringVar(&httpUrls.Username, "u", "", "The user name to use when connecting to the HTTP server")
    flagSet.StringVar(&httpUrls.FileName, "f", "", "File name")
    flagSet.BoolVar(&httpUrls.ReadPassword, "p", false, "Reads the password to use when connecting to the HTTP server")
    flagSet.BoolVar(&httpUrls.Debug, "d", false, "Show debug info")
    flagSet.Parse(os.Args[1:])

    if httpUrls.ReadPassword {
        if terminal.IsTerminal(syscall.Stdin) {
            fmt.Print("Password:")
            pwd, err := terminal.ReadPassword(syscall.Stdin)
            if err != nil {
                return nil, err
            }
            if err = httpUrls.SetPassword(pwd); err != nil {
                return nil, err
            }
        } else {
            pwd, err := ioutil.ReadAll(os.Stdin)
            if err != nil {
                return nil, err
            }
            if err = httpUrls.SetPassword(pwd); err != nil {
                return nil, err
            }
        }
    }

    urls := make(map[string]bool)
    for _, url := range flagSet.Args() {
        if _, ok := urls[url]; !ok {
            httpUrls.Urls = append(httpUrls.Urls, url)
            urls[url] = true
        }
    }

    return httpUrls, nil
}

func (this *HttpUrls) SetPassword(password []byte) error {
    block, err := aes.NewCipher(this.SecretKey)
    if err != nil {
        return err
    }
    ct := make([]byte, aes.BlockSize + len(password))

    iv := ct[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return err
    }

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ct[aes.BlockSize:], password)

    this.Password = base64.URLEncoding.EncodeToString(ct)

    return nil
}

func (this *HttpUrls) GetPassword() (string, error) {
    ct, _ := base64.URLEncoding.DecodeString(this.Password)

    block, err := aes.NewCipher(this.SecretKey)
    if err != nil {
        return "", err
    }

    iv := ct[:aes.BlockSize]
    ct = ct[aes.BlockSize:]

    stream := cipher.NewCFBDecrypter(block, iv)

    stream.XORKeyStream(ct, ct)

    return fmt.Sprintf("%s", ct), nil
}

func NewHttpUrl(httpUrls *HttpUrls, rawUrl string) *HttpUrl {
    if netUrl, err := url.Parse(rawUrl); err == nil {
        if len(netUrl.Host) > 0 {
            if strings.Index(netUrl.Host, ":") > 0 {
                var num, port int
                var loc string
                if n, err := fmt.Sscanf(netUrl.Host, "dock%d.%2s.seznam.cz:%d", &num, &loc, &port); err == nil && n == 3 {
                    netUrl.Host = fmt.Sprintf("dock%03d.%s.seznam.cz:%d", num, loc, port)
                }
            } else {
                var num int
                var loc string
                if n, err := fmt.Sscanf(netUrl.Host, "dock%d.%2s.seznam.cz", &num, &loc); err == nil && n == 2 {
                    netUrl.Host = fmt.Sprintf("dock%03d.%s.seznam.cz", num, loc)
                }
            }
            rawUrl = netUrl.String()
        }
    }

    return &HttpUrl{
        HttpUrls: httpUrls,
        Url: rawUrl,
    }
}

func (this *HttpUrl) GetHtmlDocument() (*html.Node, error) {
    req, err := this.NewHttpRequest("GET")
    if err != nil {
        return nil, err
    }

    res, err := this.HttpUrls.HttpClient.Do(req)
    if err != nil {
        return nil, err
    }

    defer res.Body.Close()

    if res.StatusCode == http.StatusOK {
        return html.Parse(res.Body)
    }

    return nil, fmt.Errorf(res.Status)
}

func (this *HttpUrl) Ls(fileNames chan<- string) {
    doc, err := this.GetHtmlDocument()
    if err == nil {
        var parseNode func(*html.Node)
        parseNode = func(n *html.Node) {
            if n.Type == html.ElementNode && n.Data == "a" {
                for _, a := range n.Attr {
                    if a.Key == "href" && a.Val != "../" {
                        val := string(a.Val)
                        if val[len(val) - 1] == '/' {
                            NewHttpUrl(this.HttpUrls, this.Url + a.Val).Ls(fileNames)
                        } else {
                            if len(this.HttpUrls.FileName) > 0 {
                                if this.HttpUrls.FileName == a.Val {
                                    fileNames <- fmt.Sprintf("%s%s", this.Url, a.Val)
                                }
                            } else {
                                fileNames <- fmt.Sprintf("%s%s", this.Url, a.Val)
                            }
                        }
                    }
                }
            }
            for c := n.FirstChild; c != nil; c = c.NextSibling {
                parseNode(c)
            }
        }
        parseNode(doc)
    } else {
        log.Println(err.Error())
    }
}

func (this *HttpUrl) ParseNode(node *html.Node, fileNames chan<- string) {
}

func (this *HttpUrl) NewHttpRequest(method string) (*http.Request, error) {
    req, err := http.NewRequest(method, this.Url, nil)
    if err != nil {
        return nil, err
    }

    if len(this.HttpUrls.Username) > 0 && len(this.HttpUrls.Password) > 0 {
        password, err := this.HttpUrls.GetPassword()
        if err != nil {
            return nil, err
        }
        req.SetBasicAuth(this.HttpUrls.Username, password)
    }

    return req, nil
}
