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
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-consent-logic/generated"
	"net/http"
)

type ApiResource struct{}

func (ApiResource) NutsConsentLogicCreateConsent(ctx echo.Context) error {
	createConsentRequest := new(generated.CreateConsentRequest)
	if err := ctx.Bind(createConsentRequest); err != nil {
		return err
	}
	return ctx.JSON(http.StatusOK, createConsentRequest)
}

func (ApiResource) NutsConsentLogicValidateConsent(ctx echo.Context) error {
	panic("implement me")
}

