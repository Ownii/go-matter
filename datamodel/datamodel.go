package datamodel

// ClusterID represents a Matter Cluster ID.
type ClusterID uint32

// AttributeID represents a Matter Attribute ID.
type AttributeID uint32

// CommandID represents a Matter Command ID.
type CommandID uint32

// EndpointID represents a Matter Endpoint ID.
type EndpointID uint16

// DeviceTypeID represents a Matter Device Type ID.
type DeviceTypeID uint32

// Cluster represents a collection of attributes and commands.
type Cluster struct {
	ID         ClusterID
	Attributes map[AttributeID]Attribute
	Commands   map[CommandID]Command
}

// Attribute represents a specific piece of data within a cluster.
type Attribute struct {
	ID       AttributeID
	Type     interface{} // Should map to TLV types
	Writable bool
	Readable bool
	// TODO: Add access control fields
}

// Command represents an action that can be invoked on a cluster.
type Command struct {
	ID        CommandID
	Direction uint8 // ClientToServer or ServerToClient
	// TODO: Define request/response structures
}

// Endpoint represents a logical device within a node.
type Endpoint struct {
	ID          EndpointID
	DeviceTypes []DeviceTypeID
	Clusters    map[ClusterID]*Cluster
}

// Node represents a physical device containing multiple endpoints.
type Node struct {
	Endpoints map[EndpointID]*Endpoint
}
