// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// SubscriptionDetail subscription detail
//
// swagger:model SubscriptionDetail
type SubscriptionDetail struct {

	// action to be setup list
	// Required: true
	ActionToBeSetupList ActionsToBeSetup `json:"ActionToBeSetupList"`

	// event triggers
	// Required: true
	EventTriggers *EventTriggerDefinition `json:"EventTriggers"`

	// xapp event instance Id
	// Required: true
	// Maximum: 65535
	// Minimum: 0
	XappEventInstanceID *int64 `json:"XappEventInstanceId"`
}

// Validate validates this subscription detail
func (m *SubscriptionDetail) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateActionToBeSetupList(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateEventTriggers(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateXappEventInstanceID(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *SubscriptionDetail) validateActionToBeSetupList(formats strfmt.Registry) error {

	if err := validate.Required("ActionToBeSetupList", "body", m.ActionToBeSetupList); err != nil {
		return err
	}

	if err := m.ActionToBeSetupList.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("ActionToBeSetupList")
		}
		return err
	}

	return nil
}

func (m *SubscriptionDetail) validateEventTriggers(formats strfmt.Registry) error {

	if err := validate.Required("EventTriggers", "body", m.EventTriggers); err != nil {
		return err
	}

	if m.EventTriggers != nil {
		if err := m.EventTriggers.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("EventTriggers")
			}
			return err
		}
	}

	return nil
}

func (m *SubscriptionDetail) validateXappEventInstanceID(formats strfmt.Registry) error {

	if err := validate.Required("XappEventInstanceId", "body", m.XappEventInstanceID); err != nil {
		return err
	}

	if err := validate.MinimumInt("XappEventInstanceId", "body", int64(*m.XappEventInstanceID), 0, false); err != nil {
		return err
	}

	if err := validate.MaximumInt("XappEventInstanceId", "body", int64(*m.XappEventInstanceID), 65535, false); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *SubscriptionDetail) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *SubscriptionDetail) UnmarshalBinary(b []byte) error {
	var res SubscriptionDetail
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
