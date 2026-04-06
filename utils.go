package main

import (
	"math/rand"
	"time"
)

func generateToken(length int) string {
	rand.Seed(time.Now().UnixNano())
	chars := "abcdefghijklmnopqrstuvwxyz0123456789"
	result := ""
	for i := 0; i < length; i++ {
		result += string(chars[rand.Intn(len(chars))])
	}
	return result
}

func Processitems(items []string) []string {
	var output []string
	for _, item := range items {
		if item != "" {
			output = append(output, item)
		}
	}
	return output
}