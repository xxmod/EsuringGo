package model

// RequireVerificate is the SMS verification request model.
type RequireVerificate struct {
	SchoolID      string `json:"schoolid"`
	Username      string `json:"username"`
	Timestamp     string `json:"timestamp"`
	Authenticator string `json:"authenticator"`
}

// ResponseRequireVerificate is the SMS verification response model.
type ResponseRequireVerificate struct {
	Phone   string `json:"phone"`
	ResInfo string `json:"resinfo"`
	ResCode string `json:"rescode"`
}
