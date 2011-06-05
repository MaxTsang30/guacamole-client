
package net.sourceforge.guacamole.protocol;

/*
 *  Guacamole - Clientless Remote Desktop
 *  Copyright (C) 2010  Michael Jumper
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

import net.sourceforge.guacamole.io.GuacamoleReader;
import net.sourceforge.guacamole.io.GuacamoleWriter;
import net.sourceforge.guacamole.GuacamoleException;
import net.sourceforge.guacamole.net.GuacamoleSocket;
import net.sourceforge.guacamole.protocol.GuacamoleInstruction.Operation;

/**
 * A GuacamoleSocket which pre-configures the connection based on a given
 * GuacamoleConfiguration, completing the initial protocol handshake before
 * accepting data for read or write.
 *
 * This is useful for forcing a connection to the Guacamole proxy server with
 * a specific configuration while disallowing the client that will be using
 * this GuacamoleSocket from manually controlling the initial protocol
 * handshake.
 *
 * @author Michael Jumper
 */
public class ConfiguredGuacamoleSocket implements GuacamoleSocket {

    private GuacamoleSocket socket;

    /**
     * Creates a new ConfiguredGuacamoleSocket which uses the given
     * GuacamoleConfiguration to complete the initial protocol handshake over
     * the given GuacamoleSocket.
     *
     * @param socket The GuacamoleSocket to wrap.
     * @param config The GuacamoleConfiguration to use to complete the initial
     *               protocol handshake.
     * @throws GuacamoleException If an error occurs while completing the
     *                            initial protocol handshake.
     */
    public ConfiguredGuacamoleSocket(GuacamoleSocket socket, GuacamoleConfiguration config) throws GuacamoleException {

        this.socket = socket;

        // Get reader and writer
        GuacamoleReader reader = socket.getReader();
        GuacamoleWriter writer = socket.getWriter();

        // Send protocol
        writer.writeInstruction(new GuacamoleInstruction(Operation.CLIENT_SELECT, config.getProtocol()));

        // Wait for server args
        GuacamoleInstruction instruction;
        do {
            instruction = reader.readInstruction();
        } while (instruction.getOperation() != Operation.SERVER_ARGS);

        // Build args list off provided names and config
        String[] args = new String[instruction.getArgs().length];
        for (int i=0; i<instruction.getArgs().length; i++) {

            String requiredArg = instruction.getArgs()[i];

            String value = config.getParameter(requiredArg);
            if (value != null)
                args[i] = value;
            else
                args[i] = "";
            
        }

        // Send args
        writer.writeInstruction(new GuacamoleInstruction(Operation.CLIENT_CONNECT, args));

    }

    @Override
    public GuacamoleWriter getWriter() {
        return socket.getWriter();
    }

    @Override
    public GuacamoleReader getReader() {
        return socket.getReader();
    }

    @Override
    public void close() throws GuacamoleException {
        socket.close();
    }

}
