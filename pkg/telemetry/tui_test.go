package telemetry

import (
	"fmt"
	"strings"
	"testing"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"eprobe/pkg/registry"
)

func newTestStreamModel() Model {
	paneDef := registry.TUIPane{
		Name:                 "Live Plaintext HTTP/HTTPS Event Stream",
		Type:                 "stream",
		InspectPayload:       "raw",
		RequestPayloadField:  "req_payload",
		ResponsePayloadField: "resp_payload",
		SearchableFields:     []string{"status_code", "method", "path"},
		Columns: []registry.ColumnHint{
			{Field: "status_code", Width: 8},
			{Field: "method", Width: 8},
			{Field: "path", Width: 24},
		},
	}

	tbl := table.New(
		table.WithColumns([]table.Column{
			{Title: "STATUS", Width: 8},
			{Title: "METHOD", Width: 8},
			{Title: "PATH", Width: 24},
		}),
		table.WithHeight(10),
	)
	tbl.Focus()

	pane := PaneModel{
		Def:        paneDef,
		Buffer:     NewEventBuffer(10000),
		Aggregator: NewAggregator(),
		Table:      tbl,
		Viewport:   viewport.New(100, 20),
		EventChan:  make(chan map[string]interface{}, 16),
	}

	return Model{
		width:           100,
		height:          30,
		termWidth:       102,
		termHeight:      30,
		keys:            keys,
		pages:           [][]PaneModel{{pane}},
		activePageIndex: 0,
		activePaneIndex: 0,
	}
}

func TestStreamInspectUsesFilteredDisplayedEvents(t *testing.T) {
	m := newTestStreamModel()

	// Seed 20 older 200 OK /v1/chat events followed by 3 matching 502 /v1/charges events
	var initialEvents []map[string]interface{}
	for i := 0; i < 20; i++ {
		initialEvents = append(initialEvents, map[string]interface{}{
			"status_code":  200,
			"method":       "POST",
			"path":         "/v1/chat",
			"req_payload":  fmt.Sprintf("chat-req-%d", i),
			"resp_payload": fmt.Sprintf("chat-ok-%d", i),
		})
	}
	for i := 0; i < 3; i++ {
		initialEvents = append(initialEvents, map[string]interface{}{
			"status_code":  502,
			"method":       "POST",
			"path":         "/v1/charges",
			"req_payload":  fmt.Sprintf("charge-req-%d", i),
			"resp_payload": fmt.Sprintf("bad-gateway-%d", i),
		})
	}

	updated, _ := m.Update(paneEventMsg{PageIdx: 0, PaneIdx: 0, Events: initialEvents})
	m = updated.(Model)

	// Apply filter "502"
	pane := &m.pages[0][0]
	pane.FilterQuery = "502"
	pane.NeedsRebuild = true
	m.syncStreamPaneTable(pane)

	if len(pane.DisplayedEvents) != 3 {
		t.Fatalf("expected 3 displayed events after filter, got %d", len(pane.DisplayedEvents))
	}

	// Stream additional mixed events incrementally while filter is active
	updated, _ = m.Update(paneEventMsg{
		PageIdx: 0,
		PaneIdx: 0,
		Events: []map[string]interface{}{
			{
				"status_code":  200,
				"method":       "GET",
				"path":         "/v1/chat",
				"req_payload":  "chat-req-extra",
				"resp_payload": "chat-ok-extra",
			},
			{
				"status_code":  502,
				"method":       "POST",
				"path":         "/v1/charges",
				"req_payload":  "charge-req-3",
				"resp_payload": "bad-gateway-3",
			},
		},
	})
	m = updated.(Model)

	pane = &m.pages[0][0]
	if len(pane.DisplayedEvents) != 4 || len(pane.FormattedRows) != 4 {
		t.Fatalf("expected 4 filtered rows/events, got rows=%d events=%d", len(pane.FormattedRows), len(pane.DisplayedEvents))
	}

	// Select filtered row index 1 (second 502 event: bad-gateway-1) and press Enter
	pane.Table.SetCursor(1)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)

	pane = &m.pages[0][0]
	if !pane.IsInspectMode {
		t.Fatalf("expected IsInspectMode=true after Enter")
	}
	if pane.InspectEvent == nil {
		t.Fatalf("expected InspectEvent to be set")
	}
	if pane.InspectEvent["status_code"] != 502 || pane.InspectEvent["path"] != "/v1/charges" {
		t.Fatalf("inspected wrong event: got status=%v path=%v", pane.InspectEvent["status_code"], pane.InspectEvent["path"])
	}
	if pane.InspectEvent["resp_payload"] != "bad-gateway-1" {
		t.Fatalf("expected resp_payload=bad-gateway-1, got %v", pane.InspectEvent["resp_payload"])
	}
	vpView := pane.Viewport.View()
	if !strings.Contains(vpView, "bad-gateway-1") {
		t.Fatalf("expected viewport to contain bad-gateway-1, got:\n%s", vpView)
	}
	if strings.Contains(vpView, "chat-ok") {
		t.Fatalf("viewport leaked unfiltered 200 OK event:\n%s", vpView)
	}
}

func TestStreamInspectEmptyFilteredResult(t *testing.T) {
	m := newTestStreamModel()
	updated, _ := m.Update(paneEventMsg{
		PageIdx: 0,
		PaneIdx: 0,
		Events: []map[string]interface{}{
			{"status_code": 200, "method": "GET", "path": "/health", "resp_payload": "ok"},
		},
	})
	m = updated.(Model)

	pane := &m.pages[0][0]
	pane.FilterQuery = "503"
	pane.NeedsRebuild = true
	m.syncStreamPaneTable(pane)

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)

	pane = &m.pages[0][0]
	if pane.InspectEvent != nil {
		t.Fatalf("expected nil InspectEvent when filter matches 0 rows, got %v", pane.InspectEvent)
	}
	if !strings.Contains(pane.Viewport.View(), "No matching events to inspect.") {
		t.Fatalf("expected empty-match message in viewport, got:\n%s", pane.Viewport.View())
	}
}
