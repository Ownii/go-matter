package interaction

import (
	"go-matter/datamodel"
	"go-matter/session"
)

// AttributeStore defines the interface for accessing the data model.
// This decouples the interaction layer from the actual data storage.
type AttributeStore interface {
	// ReadAttribute reads the value of an attribute.
	ReadAttribute(endpointID datamodel.EndpointID, clusterID datamodel.ClusterID, attributeID datamodel.AttributeID) (interface{}, error)

	// WriteAttribute writes the value of an attribute.
	WriteAttribute(endpointID datamodel.EndpointID, clusterID datamodel.ClusterID, attributeID datamodel.AttributeID, value interface{}) error
}

// InteractionModel handles the Matter Interaction Model protocol.
type InteractionModel struct {
	sessionManager *session.SessionManager
	store          AttributeStore
}

// NewInteractionModel creates a new InteractionModel.
func NewInteractionModel(sm *session.SessionManager, store AttributeStore) *InteractionModel {
	return &InteractionModel{
		sessionManager: sm,
		store:          store,
	}
}

// SendReadRequest sends a Read Request to a peer.
func (im *InteractionModel) SendReadRequest(sessionID uint16, endpointID datamodel.EndpointID, clusterID datamodel.ClusterID, attributeID datamodel.AttributeID) error {
	// TODO: Construct Read Request and send via sessionManager
	return nil
}

// HandleReadRequest processes an incoming Read Request.
func (im *InteractionModel) HandleReadRequest(sessionID uint16, payload []byte) error {
	// TODO: Parse Read Request
	// TODO: Fetch data from im.store
	// TODO: Send Report Data response
	return nil
}

// SendWriteRequest sends a Write Request to a peer.
func (im *InteractionModel) SendWriteRequest(sessionID uint16, endpointID datamodel.EndpointID, clusterID datamodel.ClusterID, attributeID datamodel.AttributeID, value interface{}) error {
	// TODO: Construct Write Request and send via sessionManager
	return nil
}

// HandleWriteRequest processes an incoming Write Request.
func (im *InteractionModel) HandleWriteRequest(sessionID uint16, payload []byte) error {
	// TODO: Parse Write Request
	// TODO: Write data to im.store
	// TODO: Send Write Response
	return nil
}
