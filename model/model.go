package model

import (
	"errors"
	"go-matter/datamodel"
	"go-matter/interaction"
)

// Fabric represents a Matter Fabric.
type Fabric struct {
	ID    uint64
	Label string
	// TODO: Add fabric-specific data
}

// DataStore implements the interaction.AttributeStore interface.
// It holds the actual state of the device.
type DataStore struct {
	node *datamodel.Node
}

// NewDataStore creates a new DataStore.
func NewDataStore() *DataStore {
	return &DataStore{
		node: &datamodel.Node{
			Endpoints: make(map[datamodel.EndpointID]*datamodel.Endpoint),
		},
	}
}

// ReadAttribute reads the value of an attribute.
func (ds *DataStore) ReadAttribute(endpointID datamodel.EndpointID, clusterID datamodel.ClusterID, attributeID datamodel.AttributeID) (interface{}, error) {
	endpoint, ok := ds.node.Endpoints[endpointID]
	if !ok {
		return nil, errors.New("endpoint not found")
	}
	cluster, ok := endpoint.Clusters[clusterID]
	if !ok {
		return nil, errors.New("cluster not found")
	}
	// TODO: Retrieve actual attribute value (currently datamodel.Attribute only holds metadata)
	_ = attributeID
	_ = cluster
	return nil, nil // Return actual value
}

// WriteAttribute writes the value of an attribute.
func (ds *DataStore) WriteAttribute(endpointID datamodel.EndpointID, clusterID datamodel.ClusterID, attributeID datamodel.AttributeID, value interface{}) error {
	endpoint, ok := ds.node.Endpoints[endpointID]
	if !ok {
		return errors.New("endpoint not found")
	}
	cluster, ok := endpoint.Clusters[clusterID]
	if !ok {
		return errors.New("cluster not found")
	}
	// TODO: Update attribute value
	_ = attributeID
	_ = value
	_ = cluster
	return nil
}

// Ensure DataStore implements interaction.AttributeStore
var _ interaction.AttributeStore = (*DataStore)(nil)
