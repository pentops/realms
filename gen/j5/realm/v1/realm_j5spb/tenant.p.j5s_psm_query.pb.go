// Code generated by protoc-gen-go-psm. DO NOT EDIT.

package realm_j5spb

import (
	context "context"
	psm "github.com/pentops/protostate/psm"
	sqrlx "github.com/pentops/sqrlx.go/sqrlx"
)

// State Query Service for %sTenant
// QuerySet is the query set for the Tenant service.

type TenantPSMQuerySet = psm.StateQuerySet[
	*TenantGetRequest,
	*TenantGetResponse,
	*TenantListRequest,
	*TenantListResponse,
	*TenantEventsRequest,
	*TenantEventsResponse,
]

func NewTenantPSMQuerySet(
	smSpec psm.QuerySpec[
		*TenantGetRequest,
		*TenantGetResponse,
		*TenantListRequest,
		*TenantListResponse,
		*TenantEventsRequest,
		*TenantEventsResponse,
	],
	options psm.StateQueryOptions,
) (*TenantPSMQuerySet, error) {
	return psm.BuildStateQuerySet[
		*TenantGetRequest,
		*TenantGetResponse,
		*TenantListRequest,
		*TenantListResponse,
		*TenantEventsRequest,
		*TenantEventsResponse,
	](smSpec, options)
}

type TenantPSMQuerySpec = psm.QuerySpec[
	*TenantGetRequest,
	*TenantGetResponse,
	*TenantListRequest,
	*TenantListResponse,
	*TenantEventsRequest,
	*TenantEventsResponse,
]

func DefaultTenantPSMQuerySpec(tableSpec psm.QueryTableSpec) TenantPSMQuerySpec {
	return psm.QuerySpec[
		*TenantGetRequest,
		*TenantGetResponse,
		*TenantListRequest,
		*TenantListResponse,
		*TenantEventsRequest,
		*TenantEventsResponse,
	]{
		QueryTableSpec: tableSpec,
		ListRequestFilter: func(req *TenantListRequest) (map[string]interface{}, error) {
			filter := map[string]interface{}{}
			return filter, nil
		},
		ListEventsRequestFilter: func(req *TenantEventsRequest) (map[string]interface{}, error) {
			filter := map[string]interface{}{}
			filter["tenant_id"] = req.TenantId
			return filter, nil
		},
	}
}

type TenantQueryServiceImpl struct {
	db       sqrlx.Transactor
	querySet *TenantPSMQuerySet
	UnsafeTenantQueryServiceServer
}

var _ TenantQueryServiceServer = &TenantQueryServiceImpl{}

func NewTenantQueryServiceImpl(db sqrlx.Transactor, querySet *TenantPSMQuerySet) *TenantQueryServiceImpl {
	return &TenantQueryServiceImpl{
		db:       db,
		querySet: querySet,
	}
}

func (s *TenantQueryServiceImpl) TenantGet(ctx context.Context, req *TenantGetRequest) (*TenantGetResponse, error) {
	resObject := &TenantGetResponse{}
	err := s.querySet.Get(ctx, s.db, req, resObject)
	if err != nil {
		return nil, err
	}
	return resObject, nil
}

func (s *TenantQueryServiceImpl) TenantList(ctx context.Context, req *TenantListRequest) (*TenantListResponse, error) {
	resObject := &TenantListResponse{}
	err := s.querySet.List(ctx, s.db, req, resObject)
	if err != nil {
		return nil, err
	}
	return resObject, nil
}

func (s *TenantQueryServiceImpl) TenantEvents(ctx context.Context, req *TenantEventsRequest) (*TenantEventsResponse, error) {
	resObject := &TenantEventsResponse{}
	err := s.querySet.ListEvents(ctx, s.db, req, resObject)
	if err != nil {
		return nil, err
	}
	return resObject, nil
}
