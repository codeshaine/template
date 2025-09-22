package router

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/spf13/viper"
)

func NewRouter() http.Handler {
	r := chi.NewRouter()

	c := cors.Handler(cors.Options{
		AllowedOrigins:   viper.GetStringSlice("server.cors.allowed_origin"),
		AllowedMethods:   viper.GetStringSlice("server.cors.allowed_methods"),
		AllowedHeaders:   viper.GetStringSlice("server.cors.allowed_headers"),
		AllowCredentials: viper.GetBool("server.cors.allow_credentials"),
	})

	r.Use(c)

	// Add your routes here
	//service and repo injection (break down if necessary)

	return r
}
