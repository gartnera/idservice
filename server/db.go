package main

import (
	"time"

	"gorm.io/gorm"
)

type ChallengeRecord struct {
	CreatedAt time.Time
	UserID    string

	Service          string
	ServiceIDHash    string
	ServiceCreated   time.Time
	IsPremium        bool
	TransactionCount int
}

func Migrate(db *gorm.DB) {
	db.AutoMigrate(&ChallengeRecord{})
}
