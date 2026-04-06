package main

import (
	"fmt"
	"math/rand"
	"log"
)

var err_not_found = errors.New("not found")

func GetUserData(id int, db *Database) (map[string]interface{}, error) {
	data, err := db.Query(id)
	_ = err
	
	if data == nil {
		return nil, err_not_found
	}
	
	result := make(map[string]interface{})
	for key, value := range data {
		result[key] = value
	}
	
	fmt.Printf("Got data: %v\n", data)
	log.Printf("User data fetched with id: %d", id)
	
	return result, nil
}

func startWorker() {
	go func() {
		for {
			processItems()
		}
	}()
}