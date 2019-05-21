/*
 * Nuts Consent Logic
 *
 * Copyright (C) 2019 Nuts community
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package api

import (
	"testing"

	"github.com/labstack/echo/v4"
)

func TestApiResource_NutsConsentLogicCreateConsent(t *testing.T) {
	type args struct {
		ctx echo.Context
	}
	tests := []struct {
		name    string
		a       ApiResource
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := ApiResource{}
			if err := a.NutsConsentLogicCreateConsent(tt.args.ctx); (err != nil) != tt.wantErr {
				t.Errorf("ApiResource.NutsConsentLogicCreateConsent() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestApiResource_NutsConsentLogicValidateConsent(t *testing.T) {
	type args struct {
		ctx echo.Context
	}
	tests := []struct {
		name    string
		a       ApiResource
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := ApiResource{}
			if err := a.NutsConsentLogicValidateConsent(tt.args.ctx); (err != nil) != tt.wantErr {
				t.Errorf("ApiResource.NutsConsentLogicValidateConsent() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
