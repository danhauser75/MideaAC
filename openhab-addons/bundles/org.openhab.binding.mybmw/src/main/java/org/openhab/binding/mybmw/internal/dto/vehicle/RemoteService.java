/**
 * Copyright (c) 2010-2023 Contributors to the openHAB project
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 */
package org.openhab.binding.mybmw.internal.dto.vehicle;

/**
 * The {@link RemoteService} Data Transfer Object
 *
 * @author Bernd Weymann - Initial contribution
 */
public class RemoteService {
    public boolean isEnabled;// ": true,
    public boolean isPinAuthenticationRequired;// ": false,
    public String executionMessage;// ": "Lock your vehicle now? Remote functions may take a few seconds."
}