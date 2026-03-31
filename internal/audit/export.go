package audit

import (
	"encoding/csv"
	"fmt"
	"io"
	"time"
)

// ExportCSV writes audit log entries to the writer in CSV format.
func ExportCSV(w io.Writer, logs []*AuditLog) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	// Header
	if err := cw.Write([]string{
		"ID", "Timestamp", "User ID", "Action",
		"Target Type", "Target ID", "Target Name",
		"IP Address", "User Agent", "Status Code",
	}); err != nil {
		return fmt.Errorf("write csv header: %w", err)
	}

	for _, log := range logs {
		targetID := ""
		if log.TargetID != nil {
			targetID = fmt.Sprintf("%d", *log.TargetID)
		}

		row := []string{
			fmt.Sprintf("%d", log.ID),
			log.CreatedAt.Format(time.RFC3339),
			fmt.Sprintf("%d", log.UserID),
			string(log.Action),
			log.TargetType,
			targetID,
			log.TargetName,
			log.IPAddress,
			log.UserAgent,
			fmt.Sprintf("%d", log.StatusCode),
		}

		if err := cw.Write(row); err != nil {
			return fmt.Errorf("write csv row: %w", err)
		}
	}

	return nil
}
