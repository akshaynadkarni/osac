package fulfillment

import (
	"context"
	"fmt"

	"google.golang.org/grpc"

	privatev1 "github.com/osac-project/osac/osac-csi-driver/internal/api/osac/private/v1"
)

// bytesPerGiB is the number of bytes in one gibibyte, used to convert CSI
// capacity (bytes) to the fulfillment Volume spec (whole GiB).
const bytesPerGiB = 1024 * 1024 * 1024

// grpcVolumeClient is the production VolumeClient. It talks to the
// fulfillment-service private Volumes API over gRPC. The fulfillment-service
// owns volume inventory and tier resolution; the operator drives the actual
// vendor-side provisioning asynchronously, so a freshly created volume starts
// in CREATING and the CSI controller polls until it reaches AVAILABLE.
type grpcVolumeClient struct {
	client privatev1.VolumesClient
}

// NewVolumeClient returns a VolumeClient backed by the fulfillment-service
// private Volumes API on the given gRPC connection. The connection is expected
// to already carry transport credentials and the per-RPC bearer token (see
// dialFulfillment in cmd/osac-csi-driver).
func NewVolumeClient(conn grpc.ClientConnInterface) VolumeClient {
	return &grpcVolumeClient{client: privatev1.NewVolumesClient(conn)}
}

// CreateVolume creates a volume through the fulfillment service. It sets
// metadata.name to the CSI volume name (the PVC ref) so a retried CreateVolume
// for the same PVC can be resolved via ListVolumes, and metadata.tenant so the
// server scopes the volume to the requesting tenant. The server rejects an
// UNSPECIFIED access mode or a non-positive size, so those surface as
// InvalidArgument to the caller. gRPC status codes (notably AlreadyExists) are
// propagated unchanged for the controller's idempotency handling.
func (c *grpcVolumeClient) CreateVolume(ctx context.Context, params CreateVolumeParams) (*VolumeInfo, error) {
	md := &privatev1.Metadata{}
	md.SetName(params.PVCRef)
	md.SetTenant(params.Tenant)

	spec := &privatev1.VolumeSpec{}
	spec.SetStorageTier(params.Tier)
	spec.SetSizeGib(bytesToGiB(params.SizeBytes))
	spec.SetAccessMode(toProtoAccessMode(params.AccessMode))

	vol := &privatev1.Volume{}
	vol.SetMetadata(md)
	vol.SetSpec(spec)

	req := &privatev1.VolumesCreateRequest{}
	req.SetObject(vol)

	resp, err := c.client.Create(ctx, req)
	if err != nil {
		return nil, err
	}
	return volumeToInfo(resp.GetObject()), nil
}

// GetVolume fetches a volume by its fulfillment id.
func (c *grpcVolumeClient) GetVolume(ctx context.Context, volumeID string) (*VolumeInfo, error) {
	req := &privatev1.VolumesGetRequest{}
	req.SetId(volumeID)

	resp, err := c.client.Get(ctx, req)
	if err != nil {
		return nil, err
	}
	return volumeToInfo(resp.GetObject()), nil
}

// ListVolumes lists volumes, optionally filtering by metadata.name. The name
// filter is used by the controller to resolve a volume created by a previous
// (retried) CreateVolume call.
func (c *grpcVolumeClient) ListVolumes(ctx context.Context, params ListVolumesParams) ([]*VolumeInfo, error) {
	req := &privatev1.VolumesListRequest{}
	if params.NameFilter != "" {
		// CEL filter expression evaluated server-side (see fulfillment-service
		// generic DAO filter language).
		req.SetFilter(fmt.Sprintf("this.metadata.name == %q", params.NameFilter))
	}

	resp, err := c.client.List(ctx, req)
	if err != nil {
		return nil, err
	}

	items := resp.GetItems()
	result := make([]*VolumeInfo, 0, len(items))
	for _, v := range items {
		result = append(result, volumeToInfo(v))
	}
	return result, nil
}

// DeleteVolume deletes a volume by its fulfillment id. The operator performs the
// vendor-side deprovision asynchronously once the record is removed.
func (c *grpcVolumeClient) DeleteVolume(ctx context.Context, volumeID string) error {
	req := &privatev1.VolumesDeleteRequest{}
	req.SetId(volumeID)

	_, err := c.client.Delete(ctx, req)
	return err
}

// bytesToGiB converts a byte count to whole GiB, rounding up so the provisioned
// volume is never smaller than requested. A non-positive input yields 0, which
// the server rejects with InvalidArgument.
func bytesToGiB(b int64) int64 {
	if b <= 0 {
		return 0
	}
	return (b + bytesPerGiB - 1) / bytesPerGiB
}

// toProtoAccessMode maps a CSI access-mode enum string
// (csi.VolumeCapability_AccessMode_Mode.String()) to the fulfillment proto
// VolumeAccessMode. The mapping mirrors the k8s external-provisioner's forward
// mapping (k8s -> CSI), reversed. Unknown values map to UNSPECIFIED, which the
// server rejects.
func toProtoAccessMode(csiMode string) privatev1.VolumeAccessMode {
	switch csiMode {
	case "SINGLE_NODE_WRITER", "SINGLE_NODE_MULTI_WRITER":
		return privatev1.VolumeAccessMode_VOLUME_ACCESS_MODE_READ_WRITE_ONCE
	case "SINGLE_NODE_SINGLE_WRITER":
		return privatev1.VolumeAccessMode_VOLUME_ACCESS_MODE_READ_WRITE_ONCE_POD
	case "SINGLE_NODE_READER_ONLY", "MULTI_NODE_READER_ONLY":
		return privatev1.VolumeAccessMode_VOLUME_ACCESS_MODE_READ_ONLY_MANY
	case "MULTI_NODE_SINGLE_WRITER", "MULTI_NODE_MULTI_WRITER":
		return privatev1.VolumeAccessMode_VOLUME_ACCESS_MODE_READ_WRITE_MANY
	default:
		return privatev1.VolumeAccessMode_VOLUME_ACCESS_MODE_UNSPECIFIED
	}
}

// volumeToInfo maps a proto Volume to the driver-internal VolumeInfo. Capacity
// is derived from the (immutable) spec size since the API tracks size in GiB.
func volumeToInfo(v *privatev1.Volume) *VolumeInfo {
	if v == nil {
		return nil
	}
	info := &VolumeInfo{
		ID:            v.GetId(),
		Name:          v.GetMetadata().GetName(),
		CapacityBytes: v.GetSpec().GetSizeGib() * bytesPerGiB,
	}
	if st := v.GetStatus(); st != nil {
		info.State = fromProtoState(st.GetState())
		info.Backend = st.GetBackend()
		info.VendorVolumeID = st.GetVendorVolumeId()
		info.Protocol = fromProtoProtocol(st.GetProtocol())
	}
	return info
}

// fromProtoState maps the proto VolumeState to the driver-internal VolumeState.
// DELETED collapses onto DELETING (both mean "gone or going"); UNSPECIFIED maps
// to the empty state, which the controller's poll loop treats as unexpected.
func fromProtoState(s privatev1.VolumeState) VolumeState {
	switch s {
	case privatev1.VolumeState_VOLUME_STATE_CREATING:
		return VolumeStateCreating
	case privatev1.VolumeState_VOLUME_STATE_AVAILABLE:
		return VolumeStateAvailable
	case privatev1.VolumeState_VOLUME_STATE_DELETING, privatev1.VolumeState_VOLUME_STATE_DELETED:
		return VolumeStateDeleting
	case privatev1.VolumeState_VOLUME_STATE_FAILED:
		return VolumeStateError
	default:
		return ""
	}
}

// fromProtoProtocol maps the proto StorageProtocol to the lowercase protocol
// string carried in the CSI volume context ("osac.protocol").
func fromProtoProtocol(p privatev1.StorageProtocol) string {
	switch p {
	case privatev1.StorageProtocol_STORAGE_PROTOCOL_NFS:
		return "nfs"
	case privatev1.StorageProtocol_STORAGE_PROTOCOL_BLOCK:
		return "block"
	default:
		return ""
	}
}
