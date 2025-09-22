package config

import (
	"log"

	"github.com/spf13/viper"
)

func LoadConfig() {
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.SetConfigName("secrets.yaml")

	err := viper.MergeInConfig()
	if err != nil {
		log.Default().Fatal(err.Error())
	}
}
