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
package codec.x509.extensions;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;

import codec.asn1.ASN1Boolean;
import codec.asn1.ASN1Exception;
import codec.asn1.ASN1Integer;
import codec.asn1.ASN1ObjectIdentifier;
import codec.asn1.ASN1Sequence;
import codec.asn1.Decoder;
import codec.x509.X509Extension;

/**
 * This extension shall be critical.
 * 
 * <pre>
 *  id-ce-extBasicConstraints OBJECT IDENTIFIER ::= {id-ce 19}
 *  BasicConstraintsSyntax ::= SEQUENCE {
 *    cA  BOOLEAN DEFAULT FALSE,
 *    pathLenConstraint INTEGER (0..MAX) OPTIONAL
 *  }
 * 
 * 	id-ce OBJECT IDENTIFIER  ::=  {joint-iso-ccitt(2) ds(5) 29}
 * 
 * </pre>
 * 
 * @author mal
 * 
 * 
 * little change : to be compatible to the ITU X690 Standard, Chapter 8,10, 11 i
 * changed the constructor BasicConstraint(boolean ca, int pathLength). in case
 * ca=false, the default value false is not encoded, this means the extension
 * contents only its oid and an empty sequence. cval
 */
public class BasicConstraintsExtension extends X509Extension {
    public static final String ID_CE_BASIC_CONSTRAINTS = "2.5.29.19";

    protected ASN1Boolean cA;

    protected ASN1Integer pathLenConstraints;

    protected ASN1Sequence basicConstraintsSyntax;

    public BasicConstraintsExtension() throws Exception {
	this(false, -1);
    }

    /**
     * 
     * @param _cA
     * @param _pathLenConstraints
     *                <0 means infit (i.e. this field won't be set
     * @throws Exception
     */
    public BasicConstraintsExtension(boolean _cA, int _pathLenConstraints)
	    throws Exception {
	// set parameters
	setOID(new ASN1ObjectIdentifier(ID_CE_BASIC_CONSTRAINTS));
	setCritical(true); // this is alway the case

	// set payload
	cA = new ASN1Boolean(_cA);
	cA.setOptional(false); // I'm in doubt if that's neccessary

	if (_cA && _pathLenConstraints >= 0) {
	    pathLenConstraints = new ASN1Integer(_pathLenConstraints);
	    pathLenConstraints.setOptional(false); // mark that it's there
	} else {
	    pathLenConstraints = new ASN1Integer(); // default set
	    pathLenConstraints.setOptional(true); // but invisible
	}

	// now put things together
	basicConstraintsSyntax = new ASN1Sequence();
	if (_cA) {
	    basicConstraintsSyntax.add(cA);
	    basicConstraintsSyntax.add(pathLenConstraints);
	}

	/*
	 * Encode payload into super class, which amounts to encoding an empty
	 * SEQUENCE. --volker roth
	 * 
	 * No, I think that's not true, because 'ca' is not optional and
	 * defaults to false. I think it won't be encoded, but that's (or at
	 * least should) be irrelevant here. --Marcus Lippert
	 */
	setValue(basicConstraintsSyntax);
    }

    /**
     * Constructor for BasicConstraintsExtension.
     * 
     * @param ext
     * @throws ASN1Exception
     * @throws IOException
     */
    public BasicConstraintsExtension(byte[] ext) throws ASN1Exception,
	    IOException {
	super(ext);
    }

    /**
     * Returns the cA.
     * 
     * @return ASN1Boolean
     */
    public boolean isCA() {
	return cA.isTrue();
    }

    /**
     * Returns the pathLenConstraints.
     * 
     * @return The path length or -1 if none is present in this extension.
     */
    public int getPathLenConstraints() {
	/*
	 * I deleted the "if" construct below because the variable is never null
	 * anyway. Rather, I inserted the missing check for OPTIONAL. --volker
	 * roth
	 * 
	 * if (pathLenConstraints == null) {...}
	 * 
	 * thanks! ­- Marcus Lippert
	 */
	if (pathLenConstraints.isOptional()) {
	    return -1;
	}
	return pathLenConstraints.getBigInteger().intValue();
    }

    /**
     * Sets the cA.
     * 
     * @param _cA
     *                The cA to set
     */
    public void setCA(boolean _cA) throws CertificateEncodingException {
	this.cA.setTrue(_cA);

	/*
	 * Now, this also requires that we declare the checked exception added
	 * above, which really creates a mess. The ghost you call come to haunt
	 * you... --volker roth
	 * 
	 * What would be better? Putting things together when encoding and
	 * mirroring all values in member variables (int and boolean in this
	 * case)? Ok, I think that will be done next;-) --Marcus Lippert
	 */
	if (!_cA) {
	    pathLenConstraints.setOptional(true);
	}
	setValue(basicConstraintsSyntax);
    }

    /**
     * Sets the pathLenConstraints.
     * 
     * @param pathLenConstraints
     *                The pathLenConstraints to set
     */
    public void setPathLenConstraints(int pathLenConstraints) throws Exception {
	if (pathLenConstraints >= 0) {
	    this.pathLenConstraints.setBigInteger(new BigInteger(Integer
		    .toString(pathLenConstraints)));
	    this.pathLenConstraints.setOptional(false);
	} else {
	    this.pathLenConstraints.setOptional(true);
	}

	/*
	 * Copy into parent again... :( --volker roth
	 */
	setValue(basicConstraintsSyntax);
    }

    public void decode(Decoder dec) throws ASN1Exception, IOException {

	super.decode(dec);

	/*
	 * Cleaned up this faulty mess...this is the most elegant
	 * workaround/hack that I can come up with. --volker roth
	 * 
	 * Where can I find out, how it works better?? There was no one
	 * responsible nor capable to help me:-( --Marcus Lippert
	 */
	super.decodeExtensionValue(basicConstraintsSyntax);
    }

    public String toString(String offset) {
	StringBuffer buf = new StringBuffer(offset
		+ "BasicConstraintsExtension [" + getOID() + "] {");

	if (isCritical()) {
	    buf.append(" (CRITICAL)\n");
	} else {
	    buf.append(" (NOT CRITICAL)\n");
	}
	buf.append(offset + "  cA: " + cA.toString() + "\n");
	if (!pathLenConstraints.isOptional()) {
	    buf.append(offset + "  pathLenConstraints: "
		    + pathLenConstraints.toString() + "\n");
	} else {
	    buf.append(offset + "  No pathLenConstraints\n");
	}
	buf.append(offset + "}\n");
	return buf.toString();
    }

}
