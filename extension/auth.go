package extension

import (
	"fmt"
	"reflect"
)

type Auth interface {
	Check(extension map[string]string, username string, password string, clientToken string) (bool)
}

func CheckExtensionUser(extension map[string]string, username string, password string, clientToken string) (map[string]string, bool){
	if extension == nil || extension["golang_type"] == ""{
		fmt.Errorf("User extension or golang_type can not be nil")
		return nil, false
	}

	newExtension := make(map[string]string)
	for k, v := range extension {
		newExtension[k] = v
	}

	golangType := newExtension["golang_type"]

	v := reflect.New(GetTypeRegistry()[golangType])

	params := make([]reflect.Value, 4)
	params[0] = reflect.ValueOf(newExtension)
	params[1] = reflect.ValueOf(username)
	params[2] = reflect.ValueOf(password)
	params[3] = reflect.ValueOf(clientToken)
	result := v.MethodByName("Check").Call(params)

	return newExtension, result[0].Interface().(bool)
}
