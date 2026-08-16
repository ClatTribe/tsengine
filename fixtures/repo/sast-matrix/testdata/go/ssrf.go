package ssrfsample
import "net/http"
func H(w http.ResponseWriter, r *http.Request) { http.Get(r.URL.Query().Get("url")) }
