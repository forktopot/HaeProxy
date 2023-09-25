package finger

import (
	"regexp"
	"strings"
)

func Iskeyword(str string, keyword []string) bool {
	var x bool
	x = true
	for _, k := range keyword {
		if strings.Contains(str, k) {
			x = x && true
		} else {
			x = x && false
		}
	}
	return x
}

func Isregular(str string, keyword []string) bool {
	var x bool
	x = true
	for _, k := range keyword {
		re := regexp.MustCompile(k)
		if re.Match([]byte(str)) {
			x = x && true
		} else {
			x = x && false
		}
	}
	return x
}

func Isregular2(str string, keyword []string) []string {
	//var x bool
	//x = true
	var information []string
	for _, k := range keyword {
		re := regexp.MustCompile(k)
		if re.Match([]byte(str)) {
			matches := re.FindAllString(str, -1)
			information = append(information, matches...)
			//x = x && true
		} else {
			//x = x && false
		}
	}
	return information
}
