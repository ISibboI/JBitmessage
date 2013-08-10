/* ========================================================================
 *
 *  This file is part of CODEC, which is a Java package for encoding
 *  and decoding ASN.1 data structures.
 *
 *  Author: Fraunhofer Institute for Computer Graphics Research IGD
 *          Department A8: Security Technology
 *          Fraunhoferstr. 5, 64283 Darmstadt, Germany
 *
 *  Rights: Copyright (c) 2004 by Fraunhofer-Gesellschaft 
 *          zur Foerderung der angewandten Forschung e.V.
 *          Hansastr. 27c, 80686 Munich, Germany.
 *
 * ------------------------------------------------------------------------
 *
 *  The software package is free software; you can redistribute it and/or 
 *  modify it under the terms of the GNU Lesser General Public License as 
 *  published by the Free Software Foundation; either version 2.1 of the 
 *  License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful, but 
 *  WITHOUT ANY WARRANTY; without even the implied warranty of 
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public 
 *  License along with this software package; if not, write to the Free 
 *  Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, 
 *  MA 02110-1301, USA or obtain a copy of the license at 
 *  http://www.fsf.org/licensing/licenses/lgpl.txt.
 *
 * ------------------------------------------------------------------------
 *
 *  The CODEC library can solely be used and distributed according to 
 *  the terms and conditions of the GNU Lesser General Public License for 
 *  non-commercial research purposes and shall not be embedded in any 
 *  products or services of any user or of any third party and shall not 
 *  be linked with any products or services of any user or of any third 
 *  party that will be commercially exploited.
 *
 *  The CODEC library has not been tested for the use or application 
 *  for a determined purpose. It is a developing version that can 
 *  possibly contain errors. Therefore, Fraunhofer-Gesellschaft zur 
 *  Foerderung der angewandten Forschung e.V. does not warrant that the 
 *  operation of the CODEC library will be uninterrupted or error-free. 
 *  Neither does Fraunhofer-Gesellschaft zur Foerderung der angewandten 
 *  Forschung e.V. warrant that the CODEC library will operate and 
 *  interact in an uninterrupted or error-free way together with the 
 *  computer program libraries of third parties which the CODEC library 
 *  accesses and which are distributed together with the CODEC library.
 *
 *  Fraunhofer-Gesellschaft zur Foerderung der angewandten Forschung e.V. 
 *  does not warrant that the operation of the third parties's computer 
 *  program libraries themselves which the CODEC library accesses will 
 *  be uninterrupted or error-free.
 *
 *  Fraunhofer-Gesellschaft zur Foerderung der angewandten Forschung e.V. 
 *  shall not be liable for any errors or direct, indirect, special, 
 *  incidental or consequential damages, including lost profits resulting 
 *  from the combination of the CODEC library with software of any user 
 *  or of any third party or resulting from the implementation of the 
 *  CODEC library in any products, systems or services of any user or 
 *  of any third party.
 *
 *  Fraunhofer-Gesellschaft zur Foerderung der angewandten Forschung e.V. 
 *  does not provide any warranty nor any liability that utilization of 
 *  the CODEC library will not interfere with third party intellectual 
 *  property rights or with any other protected third party rights or will 
 *  cause damage to third parties. Fraunhofer Gesellschaft zur Foerderung 
 *  der angewandten Forschung e.V. is currently not aware of any such 
 *  rights.
 *
 *  The CODEC library is supplied without any accompanying services.
 *
 * ========================================================================
 */
package codec.x501;

import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.StringTokenizer;

/**
 * This parser implements a subset of RFC1779. the following features are <i>not</i>
 * supported:
 * <ul>
 * <li> Object Identifiers ("OID." <oid> | "oid." <oid>) as keys.
 * <li> Multiple attributes per name component ( <attribute> "+"
 * <name-component> )
 * <li> Hexadecimal strings ( "#" <hex> )
 * <li> Names may not be put into &quot;<&quot; and &quot;<&quot;
 * </ul>
 * Quoting and escaping is fully supported, though. Keys are converted into
 * upper case. The keys are not verified. It is possible to specify keys that
 * are not defined in RFC1779 such as for instance CN, O, OU, or ST. This allows
 * the class using this parser to make decisions on which keys are acceptable.
 * Neither is double definition of keys verified. Hence, the name
 * 
 * <pre>
 * CN=Volker, CN=Roth; O=FhG, C=DE
 * </pre>
 * 
 * is parsed fine and returns as a result two attributes with the key CN.
 * <p>
 * 
 * This class uses a state machine for parsing. The states are described briefly
 * below. Each pair denotes a state transition to the state with the given
 * number that happens on reading the given input. If there is no transition
 * defined for some input then this input leads to the error condition.
 * <dl>
 * <dt> <b>0</b>
 * <dd> (*CHAR, 1)
 * <dt> <b>1</b>
 * <dd> ('=', 2)
 * <dt> <b>2</b>
 * <dd> (SEPARATOR, 0), (ESCAPE, 3), (*SPACE, 2), (*CHAR, 5), (QUOTE, 4)
 * <dt> <b>3</b>
 * <dd> (SPECIAL, 5)
 * <dt> <b>4</b>
 * <dd> (QUOTE, 7), (ESCAPE, 6), (*CHAR, 4)
 * <dt> <b>5</b>
 * <dd> (ESCAPE, 3), (SEPARATOR, 0), (*CHAR, 5)
 * <dt> <b>6</b>
 * <dd> (SPECIAL, 4)
 * <dt> <b>7</b>
 * <dd> (SEPARATOR, 0), (*SPACE, 7)
 * </dl>
 * The states 2, 5 and 7 are final states. The machine starts in state 0. In
 * other words, no empty input is accepted.
 * 
 * @author Volker Roth
 * @version "$Id: RFC1779Parser.java,v 1.6 2007/08/30 08:45:05 pebinger Exp $"
 * @deprecated
 */
public class RFC1779Parser {
    /**
     * Characters that must be escaped with a backslash.
     */
    public static final String SPECIALS = ",+=\"<>\n#;\\";

    /**
     * Delimiters for the StringTokenizer
     */
    public static final String SEPARATORS = ",;";

    /**
     * The pair introducer.
     */
    public static final String ESCAPE = "\\";

    /**
     * The quote character.
     */
    public static final String QUOTE = "\"";

    /**
     * The list of attributes in the order they were parsed.
     */
    protected LinkedList klist_ = new LinkedList();

    /**
     * The list of values in the order they were parsed.
     */
    protected LinkedList vlist_ = new LinkedList();

    public static void main(String[] argv) {
	int n;
	Iterator i;
	RFC1779Parser parser;
	Entry entry;

	parser = new RFC1779Parser();
	for (n = 0; n < argv.length; n++) {
	    System.out.println("Arg is: '" + argv[n] + "'");

	    try {
		i = parser.parse(argv[n]);

		while (i.hasNext()) {
		    entry = (Entry) i.next();

		    System.out.println("'" + (String) entry.getKey() + "="
			    + (String) entry.getValue() + "'");
		}
	    } catch (Exception e) {
		e.printStackTrace();
	    }
	}
    }

    /**
     * Class constructor
     */
    public RFC1779Parser() {
	super();
    }

    /**
     * This method parses the given name.
     * 
     * @param rfc1779name
     *                The name string that is parsed into its components.
     * @throws BadNameException
     *                 if the syntax of the name string is not correct.
     */
    public Iterator parse(String rfc1779name) throws BadNameException {
	StringTokenizer st;
	StringBuffer value;
	String tok;
	String key;
	int state;

	state = 0;
	key = new String();
	value = new StringBuffer();
	st = new StringTokenizer(rfc1779name, SPECIALS, true);

	klist_.clear();
	vlist_.clear();

	while (st.hasMoreTokens()) {
	    tok = st.nextToken();

	    switch (state) {
	    case 0:
		if (SPECIALS.indexOf(tok.charAt(0)) < 0) {
		    key = tok.trim();
		    klist_.addFirst(key);
		    state = 1;
		    continue;
		}
		throw new BadNameException("(" + state + ") "
			+ "Key starts with SPECIAL '" + tok + "'!");

	    case 1:
		if (tok.equals("=")) {
		    state = 2;
		    continue;
		}
		throw new BadNameException("(" + state + ") "
			+ "'=' expected after '" + key + "'!");

	    case 2:
		if (tok.equals(ESCAPE)) {
		    state = 3;
		    continue;
		}
		if (tok.equals(QUOTE)) {
		    state = 4;
		    continue;
		}
		if (SEPARATORS.indexOf(tok.charAt(0)) >= 0) {
		    vlist_.addFirst(new String());
		    state = 0;
		    continue;
		}
		if (SPECIALS.indexOf(tok.charAt(0)) < 0) {
		    if (tok.trim().length() > 0) {
			value.append(tok);
			state = 5;
		    }
		    continue;
		}
		throw new BadNameException("(" + state + ") "
			+ "Unescaped or quoted SPECIAL '" + tok + "' after '"
			+ key + "'!");

	    case 3:
		if (SPECIALS.indexOf(tok.charAt(0)) >= 0) {
		    value.append(tok);
		    state = 5;
		    continue;
		}
		throw new BadNameException("(" + state + ") "
			+ "Can't ESCAPE non-special character!");

	    case 4:
		if (tok.equals(QUOTE)) {
		    vlist_.addFirst(value.toString().trim());
		    value.setLength(0);
		    state = 7;
		    continue;
		}
		if (tok.equals(ESCAPE)) {
		    state = 6;
		    continue;
		}
		if (SPECIALS.indexOf(tok.charAt(0)) < 0) {
		    value.append(tok);
		    continue;
		}
		throw new BadNameException("(" + state + ") "
			+ "Unescaped SPECIAL '" + tok + "' in value of '" + key
			+ "'!");

	    case 5:
		if (tok.equals(ESCAPE)) {
		    state = 3;
		    continue;
		}
		if (SPECIALS.indexOf(tok.charAt(0)) < 0) {
		    value.append(tok);
		    continue;
		}
		if (SEPARATORS.indexOf(tok.charAt(0)) >= 0) {
		    vlist_.addFirst(value.toString().trim());
		    value.setLength(0);
		    state = 0;
		    continue;
		}
		throw new BadNameException("(" + state + ") "
			+ "Unescaped SPECIAL '" + tok + "' in value of '" + key
			+ "'!");

	    case 6:
		if (SPECIALS.indexOf(tok.charAt(0)) >= 0) {
		    value.append(tok);
		    state = 4;
		    continue;
		}
		throw new BadNameException("(" + state + ") "
			+ "Can't ESCAPE non-special character!");

	    case 7:
		if (SEPARATORS.indexOf(tok.charAt(0)) >= 0) {
		    state = 0;
		    continue;
		}
		if (tok.trim().length() == 0) {
		    continue;
		}
		throw new BadNameException("(" + state + ") "
			+ "SEPARATOR expected!");
	    }
	}
	/*
	 * We first check if the state machine is in a final state.
	 */
	if (state != 7 && state != 2 && state != 5) {
	    throw new BadNameException("(" + state + ") "
		    + "Not in a final state!");
	}
	/*
	 * We have to check for the epsilon transitions of the final states.
	 */
	if (state == 2 || state == 5) {
	    vlist_.addFirst(value.toString().trim());
	}
	return new Entry(klist_, vlist_);
    }

    /**
     * This class serves as Iterator as well as an entry object.
     */
    public class Entry extends Object implements Iterator {
	private Iterator kl_;
	private Iterator vl_;

	private Object k_;
	private Object v_;

	Entry(List k, List v) {
	    kl_ = k.iterator();
	    vl_ = v.iterator();
	}

	public boolean hasNext() {
	    return kl_.hasNext() && vl_.hasNext();
	}

	public Object next() {
	    k_ = kl_.next();
	    v_ = vl_.next();

	    return this;
	}

	public Object getKey() {
	    return k_;
	}

	public Object getValue() {
	    return v_;
	}

	public void remove() {
	    throw new UnsupportedOperationException("I don't remove!");
	}
    }

}
