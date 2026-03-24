package endpoint

import (
	"encoding/json"
	"time"
)

// OsqueryResult represents a single row from an osquery result log.
type OsqueryResult struct {
	Name           string            `json:"name"`
	HostIdentifier string            `json:"hostIdentifier"`
	CalendarTime   string            `json:"calendarTime"`
	UnixTime       int64             `json:"unixTime"`
	Action         string            `json:"action"`
	Columns        map[string]string `json:"columns"`
}

// OsqueryBatch represents a batch of osquery results.
type OsqueryBatch struct {
	NodeKey string          `json:"node_key"`
	Results []OsqueryResult `json:"results"`
}

// NormalizeOsqueryEvents converts osquery results into EndpointEvents.
func NormalizeOsqueryEvents(batch *OsqueryBatch, hostnameUserMap map[string]int64) []*EndpointEvent {
	events := make([]*EndpointEvent, 0, len(batch.Results))

	for _, result := range batch.Results {
		event := &EndpointEvent{
			Hostname:  result.HostIdentifier,
			EventType: mapOsqueryAction(result.Name, result.Action),
			FileName:  result.Columns["target_path"],
			FilePath:  result.Columns["target_path"],
			ProcessName: result.Columns["process"],
			Source:    "osquery",
			EventTime: time.Unix(result.UnixTime, 0),
		}

		if userID, ok := hostnameUserMap[result.HostIdentifier]; ok {
			event.UserID = &userID
		}

		// Store full columns as detail
		if detail, err := json.Marshal(result.Columns); err == nil {
			event.Detail = detail
		}

		events = append(events, event)
	}

	return events
}

func mapOsqueryAction(queryName, action string) EventType {
	switch queryName {
	case "file_events":
		switch action {
		case "CREATED", "UPDATED":
			return EventFileWrite
		case "DELETED":
			return EventFileDelete
		case "MOVED":
			return EventFileRename
		default:
			return EventFileOpen
		}
	case "usb_devices":
		return EventUSBMount
	case "process_events":
		return EventProcessExec
	default:
		return EventType(queryName + "." + action)
	}
}
