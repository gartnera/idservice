package main

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"

	"github.com/go-fuego/fuego"
	"gopkg.in/yaml.v3"
)

// DataOrTemplate is a struct that can return either data or a template
// depending on the asked type.
type DataOrTemplate[T any] struct {
	Data       T
	TemplateFn func(T) fuego.Renderer
}

var (
	_ fuego.CtxRenderer = DataOrTemplate[any]{} // Can render HTML (template)
	_ json.Marshaler    = DataOrTemplate[any]{} // Can render JSON (data)
	_ xml.Marshaler     = DataOrTemplate[any]{} // Can render XML (data)
	_ yaml.Marshaler    = DataOrTemplate[any]{} // Can render YAML (data)
	_ fmt.Stringer      = DataOrTemplate[any]{} // Can render string (data)
)

func (m DataOrTemplate[T]) MarshalJSON() ([]byte, error) {
	return json.Marshal(m.Data)
}

func (m DataOrTemplate[T]) MarshalXML(e *xml.Encoder, _ xml.StartElement) error {
	return e.Encode(m.Data)
}

func (m DataOrTemplate[T]) MarshalYAML() (interface{}, error) {
	return m.Data, nil
}

func (m DataOrTemplate[T]) String() string {
	return fmt.Sprintf("%v", m.Data)
}

func (m DataOrTemplate[T]) Render(c context.Context, w io.Writer) error {
	renderer := m.TemplateFn(m.Data)
	return renderer.Render(w)
}

// Helper function to create a DataOrTemplate return item without specifying the type.
func DataOrHTMLFn[T any](data T, templateFn func(T) fuego.Renderer) *DataOrTemplate[T] {
	return &DataOrTemplate[T]{
		Data:       data,
		TemplateFn: templateFn,
	}
}
