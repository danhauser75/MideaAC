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
package org.openhab.binding.deutschebahn.internal.filter;

import org.eclipse.jdt.annotation.NonNullByDefault;

/**
 * A token representing a conjunction.
 * 
 * @author Sönke Küper - Initial contribution.
 */
@NonNullByDefault
public final class AndOperator extends OperatorToken {

    /**
     * Creates new {@link AndOperator}.
     */
    public AndOperator(int position) {
        super(position);
    }

    @Override
    public String toString() {
        return "&";
    }

    @Override
    public <R> R accept(FilterTokenVisitor<R> visitor) throws FilterParserException {
        return visitor.handle(this);
    }
}