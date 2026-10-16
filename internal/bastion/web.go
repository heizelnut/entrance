package bastion

import "embed"

//go:embed web/*
var webFS embed.FS

//go:embed static/*
var staticFS embed.FS
