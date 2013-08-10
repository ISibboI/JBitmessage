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
package codec.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;

/**
 * Decodes ASN.1/DER encoded types according to the rules set forth in ITU-T
 * Recommendation X.690.
 * <p>
 * 
 * Decoders can be operated in two modi. The first mode just reads any ASN.1
 * type encountered in a stream and returns the instantiated objects. This mode
 * is used if for instance method {@link #readType() readType()} is called.
 * <p>
 * 
 * The second mode matches the decoded data against an application-specified
 * ASN.1 structure. Violations of the structure definition causes an exception
 * being thrown.
 * 
 * @author Volker Roth
 * @version "$Id: BERDecoder.java,v 1.3 2001/01/08 18:47:37 vroth Exp $"
 */
public class BERDecoder extends DERDecoder {

    /**
     * Creates an instance that reads from the given input stream.
     * 
     * @param in
     *                The input stream to read from.
     */
    public BERDecoder(InputStream in) {
	super(in);
    }

    /**
     * Reads in a sequence of ASN.1 types and stores them in the given
     * collection. This method overrides a method in the parent class in order
     * to handle indefinite length encodings as required by BER. Indefinite
     * length encodings are detected by checking the
     * {@link #indefinite_ indefinite_} field in this instance. This field is
     * initialized by method {@link DERDecoder#readNext() readNext()} when the
     * identifier and length octets of the next ASN.1 type in the stream are
     * parsed.
     * 
     * @param c
     *                The ASN.1 collection in which decoded types are stored.
     * @throws ASN1Exception
     *                 if a decoding error occurs.
     * @throws IOException
     *                 if guess what...
     */
    protected void readTypes(ASN1Collection c) throws ASN1Exception,
	    IOException {
	if (indefinite_) {
	    ASN1Type o;

	    while ((o = readType()) != null) {
		c.add(o);
	    }
	} else {
	    super.readTypes(c);
	}
    }

    public void readBitString(ASN1BitString t) throws ASN1Exception,
	    IOException {
	match1(t);
	skipNext(true);

	if (primitive_) {
	    super.readBitString(t);
	    return;
	}
	/*
	 * We now make the decoder believe it encountered a sequence and tell it
	 * to skip reading the next header. Then, we actually decode a SEQUENCE
	 * OF BIT STRING. After decoding the consecutive segments of bit strings
	 * we assemble them back into a single one while checking the
	 * constraints. All necessary flags are still in place.
	 */
	ByteArrayOutputStream bos;
	ASN1SequenceOf seq;
	ASN1BitString v;
	Iterator i;
	byte[] buf;
	int pad;
	int n;

	seq = new ASN1SequenceOf(ASN1BitString.class);
	tag_ = ASN1.TAG_SEQUENCE;
	tagclass_ = ASN1.CLASS_UNIVERSAL;

	seq.decode(this);

	pad = 0;
	bos = new ByteArrayOutputStream();
	try {
	    for (i = seq.iterator(); i.hasNext();) {
		v = (ASN1BitString) i.next();
		bos.write(v.getBytes());

		n = pad;
		pad = v.getPadCount();

		if (pad != 0 && n != 0) {
		    throw new ASN1Exception(
			    "Pad count mismatch in BIT STRING segment!");
		}
	    }
	    buf = bos.toByteArray();
	    bos.close();

	    t.setBits(buf, pad);
	} catch (ClassCastException e) {
	    throw new ASN1Exception(
		    "Type mismatch in BER encoded BIT STRING segment!");
	}
    }

    public void readOctetString(ASN1OctetString t) throws ASN1Exception,
	    IOException {
	match1(t);

	/*
	 * We have to skip in any case. Either in order to allow our super class
	 * to match once again or to let the SEQUENCE match the faked type if we
	 * came across a CONSTRUCTED encoding (BER).
	 */
	skipNext(true);

	if (primitive_) {
	    super.readOctetString(t);
	    return;
	}
	/*
	 * We now make the decoder believe it encountered a sequence and tell it
	 * to skip reading the next header. Then, we actually decode a SEQUENCE
	 * OF OCTET STRING. After decoding the consecutive segments of octet
	 * strings we assemble them back into a single one while checking the
	 * constraints. All necessary flags are still in place.
	 */
	ByteArrayOutputStream bos;
	ASN1SequenceOf seq;
	ASN1OctetString v;
	Iterator i;
	byte[] buf;

	seq = new ASN1SequenceOf(ASN1OctetString.class);
	tag_ = ASN1.TAG_SEQUENCE;
	tagclass_ = ASN1.CLASS_UNIVERSAL;
	seq.decode(this);

	bos = new ByteArrayOutputStream();
	try {
	    for (i = seq.iterator(); i.hasNext();) {
		v = (ASN1OctetString) i.next();
		bos.write(v.getByteArray());
	    }
	    buf = bos.toByteArray();
	    bos.close();
	} catch (ClassCastException e) {
	    throw new ASN1Exception(
		    "Type mismatch in BER encoded OCTET STRING segment!");
	}
	t.setByteArray(buf);
    }

    public void readString(ASN1String t) throws ASN1Exception, IOException {
	match1(t);
	skipNext(true);

	if (primitive_) {
	    super.readString(t);
	    return;
	}
	/*
	 * String types are encoded always as if they were declared [UNIVERSAL
	 * x] IMPLICIT OCTET STRING. BER decoding strings thus is reduced to
	 * parsing the (potentially constructed) encoding of an octet string.
	 * 
	 * For this reason, we make the decoder believe that it encountered an
	 * OCTET STRING and delegate decoding to the appropriate method. Apart
	 * from the tag, all flags and values such as length_ and indefinite_
	 * are already set correctly.
	 */
	ASN1OctetString v;

	v = new ASN1OctetString();
	tag_ = ASN1.TAG_OCTETSTRING;
	tagclass_ = ASN1.CLASS_UNIVERSAL;

	v.decode(this);
	t.setString(t.convert(v.getByteArray()));
    }

    public void readCollection(ASN1Collection t) throws ASN1Exception,
	    IOException {
	Iterator i;
	ASN1Type o;
	boolean vlen;
	int end;
	int n;

	match0(t, false);

	end = pos_ + length_;
	vlen = indefinite_;
	i = t.iterator();
	n = 0;

	/*
	 * The first loop is to check whether all types defined in the
	 * collection are actually present in the encoding. Mismatches caused by
	 * OPTIONAL elements of the given collection are ignored. Exceptions are
	 * triggered only if a length mismatch is detected.
	 */
	while (i.hasNext()) {
	    if (!readNext()) {
		break;
	    }
	    skipNext(true);
	    o = (ASN1Type) i.next();
	    n++;

	    if (o.isType(tag_, tagclass_)) {
		o.decode(this);
		o.setOptional(false);

		if (vlen) {
		    continue;
		}
		if (pos_ == end) {
		    break;
		}
		if (pos_ > end) {
		    throw new ASN1Exception("Length short by " + (pos_ - end)
			    + " octets!");
		}
	    } else {
		if (!o.isOptional()) {
		    throw new ASN1Exception("ASN.1 type mismatch!"
			    + "\nExpected: " + o.getClass().getName()
			    + "\nIn      : " + t.getClass().getName()
			    + "\nAt index: " + (n - 1) + "\nGot tag : " + tag_
			    + " and class: " + tagclass_);
		}
	    }
	}
	/*
	 * The second loop checks for remaining elements in the given
	 * collection, after the specified number of contents octets are read or
	 * the end of the stream was reached.
	 */
	while (i.hasNext()) {
	    o = (ASN1Type) i.next();
	    n++;

	    if (!o.isOptional()) {
		throw new ASN1Exception("ASN.1 type missing!" + "\nExpected: "
			+ o.getClass().getName() + "\nIn      : "
			+ t.getClass().getName() + "\nAt index: " + (n - 1));
	    }
	}
	/*
	 * If we decode definite length encodings then we have to verify the
	 * number of contents octets read. If we decode indefinite length
	 * encodings then we have to check for the EOC.
	 */
	if (vlen) {
	    /*
	     * This should work fine because the current tag in tag_ is
	     * invalidated if the end of stream is reached. Hence, missing EOC
	     * cause a mismatch exception even at the end of the stream.
	     */
	    match2(ASN1.TAG_EOC, ASN1.CLASS_UNIVERSAL);
	} else {
	    if (pos_ < end) {
		throw new ASN1Exception("Bad length, " + (end - pos_)
			+ " contents octets left!");
	    }
	}
    }

    public void readCollectionOf(ASN1CollectionOf t) throws ASN1Exception,
	    IOException {
	ASN1Type o;
	boolean vlen;
	int end;

	match0(t, false);

	t.clear();

	vlen = indefinite_;
	end = pos_ + length_;

	while (true) {
	    if (!vlen) {
		if (pos_ == end) {
		    return;
		}
		if (pos_ > end) {
		    throw new ASN1Exception("Read " + (pos_ - end)
			    + " octets too much!");
		}
	    }
	    if (!readNext()) {
		if (vlen) {
		    throw new ASN1Exception("EOC missing at EOF!");
		}
		throw new ASN1Exception("Bad length!");
	    }
	    if (vlen && (tag_ == ASN1.TAG_EOC)
		    && (tagclass_ == ASN1.CLASS_UNIVERSAL)) {
		return;
	    }
	    try {
		skipNext(true);
		o = t.newElement();
		o.decode(this);
	    } catch (IllegalStateException e) {
		throw new ASN1Exception("Cannot create new element! ");
	    }
	}
    }

    public void readTaggedType(ASN1TaggedType t) throws ASN1Exception,
	    IOException {
	ASN1Type o;
	boolean vlen;

	match1(t);

	vlen = indefinite_;
	o = t.getInnerType();

	if (o.isExplicit() && primitive_) {
	    throw new ASN1Exception("PRIMITIVE vs. CONSTRUCTED mismatch!");
	}
	/*
	 * A nasty trick to make the construction [CLASS TAG] IMPLICIT OCTET
	 * STRING work for types that are CONSTRUCTED.
	 */
	if (t instanceof ASN1Opaque) {
	    if (vlen) {
		throw new ASN1Exception(
			"Cannot decode indefinite length encodings "
				+ "with ASN1Opaque type!");
	    }
	    primitive_ = true;
	}
	o.decode(this);

	/*
	 * If the length encoding is INDEFINITE and the tagging is EXPLICIT then
	 * the contents octets of the tagged type must be the complete encoding
	 * of the inner type, including the EOC. Otherwise, the contents octets
	 * must be the contents octets of the inner type. In that case, the EOC
	 * is read by the code that decodes the inner type (if the inner type is
	 * CONSTRUCTED). See X.690 for details.
	 */
	if (vlen && o.isExplicit()) {
	    /*
	     * If the encoding is INDEFINITE LENGTH then we have to eat an EOC
	     * at the end of the encoding, in addition to the encoding of the
	     * underlying type.
	     */
	    match2(ASN1.TAG_EOC, ASN1.CLASS_UNIVERSAL);
	}
    }
}
