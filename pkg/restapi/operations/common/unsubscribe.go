// Code generated by go-swagger; DO NOT EDIT.

package common

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	middleware "github.com/go-openapi/runtime/middleware"
)

// UnsubscribeHandlerFunc turns a function with the right signature into a unsubscribe handler
type UnsubscribeHandlerFunc func(UnsubscribeParams) middleware.Responder

// Handle executing the request and returning a response
func (fn UnsubscribeHandlerFunc) Handle(params UnsubscribeParams) middleware.Responder {
	return fn(params)
}

// UnsubscribeHandler interface for that can handle valid unsubscribe params
type UnsubscribeHandler interface {
	Handle(UnsubscribeParams) middleware.Responder
}

// NewUnsubscribe creates a new http.Handler for the unsubscribe operation
func NewUnsubscribe(ctx *middleware.Context, handler UnsubscribeHandler) *Unsubscribe {
	return &Unsubscribe{Context: ctx, Handler: handler}
}

/*Unsubscribe swagger:route DELETE /subscriptions/{subscriptionId} common unsubscribe

Unsubscribe X2AP events from Subscription Manager

*/
type Unsubscribe struct {
	Context *middleware.Context
	Handler UnsubscribeHandler
}

func (o *Unsubscribe) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewUnsubscribeParams()

	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params) // actually handle the request

	o.Context.Respond(rw, r, route.Produces, route, res)

}