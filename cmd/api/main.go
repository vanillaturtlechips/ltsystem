package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

type TrafficData struct {
	VehicleID string    `json:"vehicle_id"`
	Speed     int       `json:"speed"`
	Timestamp time.Time `json:"timestamp"`
}

type TrafficResponse struct {
	Status  string        `json:"status"`
	Message string        `json:"message"`
	Data    []TrafficData `json:"data"`
}

type TrafficService struct {
	DB *sql.DB
}

type TrafficAPI struct {
	Service *TrafficService
}

func InitDB(connStr string) (*sql.DB, error) {
	db, err := sql.Open("mysql", connStr)
	if err != nil {
		return nil, fmt.Errorf("DB Connet fail: %w", err)
	}

	if err = db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("DB Ping Fail: %w", err)
	}
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(5 * time.Minute)

	log.Println("Database connection pool initalized successfully")
	return db, nil
}

func (api *TrafficAPI) GetTrafficDataHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	query := "SELECT VehicleID, Speed, Timestamp FROM realtime_traffic_data LIMIT 2"

	rows, err := api.Service.DB.Query(query)
	if err != nil {
		log.Printf("DB Query Error: %v", err)
		http.Error(w, "Internal Server Error during DB query", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	data := []TrafficData{}
	for rows.Next() {
		var td TrafficData

		if err := rows.Scan(&td.VehicleID, &td.Speed, &td.Timestamp); err != nil {
			log.Printf("DB Scan Error: %v", err)
			continue
		}

		data = append(data, td)
	}

	response := TrafficResponse{
		Status:  "success",
		Message: fmt.Sprintf("Retrieved %d records from DB", len(data)),
		Data:    data,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

func main() {
	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		log.Fatal("DATABASE_URL NOT SET env")
	}

	db, err := InitDB(connStr)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	service := &TrafficService{DB: db}
	api := &TrafficAPI{Service: service}

	mux := http.NewServeMux()

	mux.HandleFunc("/health/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "OK")
	})

	mux.HandleFunc("/api/v1/traffic/", api.GetTrafficDataHandler)

	port := 8080
	log.Printf("Starting GO LTS API Server on: %d", port)

	if err := http.ListenAndServe(fmt.Sprintf(":%d", port), mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
