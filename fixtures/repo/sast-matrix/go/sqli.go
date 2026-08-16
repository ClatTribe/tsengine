package main
import ("database/sql";"net/http")
func H(db *sql.DB, w http.ResponseWriter, r *http.Request){ db.Query("SELECT * FROM u WHERE n='"+r.URL.Query().Get("n")+"'") }
