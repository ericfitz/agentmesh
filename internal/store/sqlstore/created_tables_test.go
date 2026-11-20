package sqlstore

import (
	"reflect"
	"testing"
)

func TestCreatedTables(t *testing.T) {
	src := "-- CREATE TABLE commented (x INT);\nCREATE TABLE a (x INT);\n  create table if not exists b (\n x INT);\nCREATE VIRTUAL TABLE c USING fts5(x);\nINSERT INTO a VALUES (1);\nCREATE INDEX i ON a (x);\n"
	want := []string{"a", "b", "c"}
	if got := CreatedTables(src); !reflect.DeepEqual(got, want) {
		t.Fatalf("CreatedTables = %v, want %v", got, want)
	}
}
