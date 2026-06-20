package supplychain

// DefaultEOLCorpus is the checked-in snapshot of end-of-life dates for widely
// used runtimes and frameworks, sourced from the public endoflife.date dataset.
// Only already-past or near-term cycles of high-prevalence products are kept so
// the embedded default is meaningful; `corpus refresh` ingests the full feed.
// Dates are the vendor's published end-of-(security)-support dates.
func DefaultEOLCorpus() []EOLEntry {
	return []EOLEntry{
		// Language runtimes
		{Name: "python", Cycle: "2.7", EOLDate: "2020-01-01", Note: "Python 2 is permanently retired."},
		{Name: "python", Cycle: "3.6", EOLDate: "2021-12-23"},
		{Name: "python", Cycle: "3.7", EOLDate: "2023-06-27"},
		{Name: "python", Cycle: "3.8", EOLDate: "2024-10-07"},
		{Name: "nodejs", Cycle: "12", EOLDate: "2022-04-30"},
		{Name: "nodejs", Cycle: "14", EOLDate: "2023-04-30"},
		{Name: "nodejs", Cycle: "16", EOLDate: "2023-09-11"},
		{Name: "nodejs", Cycle: "18", EOLDate: "2025-04-30"},
		{Name: "php", Cycle: "7.4", EOLDate: "2022-11-28"},
		{Name: "php", Cycle: "8.0", EOLDate: "2023-11-26"},
		{Name: "php", Cycle: "8.1", EOLDate: "2025-12-31"},
		{Name: "ruby", Cycle: "2.7", EOLDate: "2023-03-31"},
		{Name: "ruby", Cycle: "3.0", EOLDate: "2024-04-23"},
		{Name: "dotnet", Cycle: "3.1", EOLDate: "2022-12-13"},
		{Name: "dotnet", Cycle: "5.0", EOLDate: "2022-05-10"},
		{Name: "dotnet", Cycle: "6.0", EOLDate: "2024-11-12"},

		// Frameworks (appear in the dependency SBOM)
		{Name: "django", Cycle: "2.2", EOLDate: "2022-04-11"},
		{Name: "django", Cycle: "3.0", EOLDate: "2021-08-03"},
		{Name: "django", Cycle: "3.1", EOLDate: "2021-12-07"},
		{Name: "django", Cycle: "3.2", EOLDate: "2024-04-01"},
		{Name: "django", Cycle: "4.0", EOLDate: "2023-04-01"},
		{Name: "rails", Cycle: "5.2", EOLDate: "2022-06-01"},
		{Name: "rails", Cycle: "6.0", EOLDate: "2023-06-01"},
		{Name: "laravel", Cycle: "8", EOLDate: "2023-01-24"},
		{Name: "laravel", Cycle: "9", EOLDate: "2024-02-08"},
		{Name: "spring-boot", Cycle: "2.6", EOLDate: "2023-11-24"},
		{Name: "spring-boot", Cycle: "2.7", EOLDate: "2025-08-31"},
		{Name: "symfony", Cycle: "4.4", EOLDate: "2023-11-30"},
		{Name: "angular", Cycle: "14", EOLDate: "2023-11-18"},
		{Name: "angular", Cycle: "15", EOLDate: "2024-05-18"},
	}
}
