package version

var (
	Version   = "1.0.0"
	Commit    = "unknown"
	BuildDate = "unknown"
)

type Info struct {
	Product   string `json:"product"`
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
}

func Current() Info {
	return Info{Product: "IRONCLAD Chimera", Version: Version, Commit: Commit, BuildDate: BuildDate}
}
