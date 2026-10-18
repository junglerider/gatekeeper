package utils

// helpers and utilities

import "encoding/json"

// convert JSON string to JSON data
func StrToJSON(s *string) (*any, error) {
	var err error
	if s != nil {
		var jsonData any
		err = json.Unmarshal([]byte(*s), &jsonData)
		if err == nil {
			return &jsonData, nil
		}
	}
	return nil, err
}

// convert a JSON data to JSON string
func JSONToStr(jsonData *any) (*string, error) {
	var err error
	if jsonData != nil {
		var bytes []byte
		bytes, err = json.Marshal(jsonData)
		if err == nil {
			s := string(bytes)
			return &s, nil
		}
	}
	return nil, err
}
