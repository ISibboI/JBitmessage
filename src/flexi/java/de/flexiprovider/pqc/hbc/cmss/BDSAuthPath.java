package de.flexiprovider.pqc.hbc.cmss;

import codec.asn1.ASN1Integer;
import codec.asn1.ASN1OctetString;
import codec.asn1.ASN1Sequence;
import de.flexiprovider.api.MessageDigest;
import de.flexiprovider.common.util.ASN1Tools;
import de.flexiprovider.common.util.ByteUtils;
import de.flexiprovider.pqc.hbc.PRNG;
import de.flexiprovider.pqc.hbc.ots.OTS;

public class BDSAuthPath {

    // variables for constructor
    private int H;

    private int K;

    protected MessageDigest md;

    protected OTS ots;

    protected PRNG prng;

    // variables for initializeSetup
    private byte[][] auth;

    private byte[][] seed;

    private Stack stack;

    private Treehash[] treehash;

    private Stack[] retain;

    private byte[][] keep;

    private byte[] leftLeaf;

    // variables for initializeUpdate
    private byte[] tmpNode;
    private byte[][] tmpStack;
    private int[] params;

    // way to compute nodes
    private NodeCalc nodeCalc;

    public BDSAuthPath(ASN1Sequence authData) {

	H = ASN1Tools.getFlexiBigInt((ASN1Integer) authData.get(0)).intValue();
	K = ASN1Tools.getFlexiBigInt((ASN1Integer) authData.get(1)).intValue();

	int nextEntry = 2;

	auth = new byte[H][];
	for (int i = 0; i < H; i++) {
	    auth[i] = ((ASN1OctetString) authData.get(nextEntry))
		    .getByteArray();
	    nextEntry++;
	}

	seed = new byte[H - K][];
	for (int i = 0; i < H - K; i++) {
	    seed[i] = ((ASN1OctetString) authData.get(nextEntry))
		    .getByteArray();
	    nextEntry++;
	}

	stack = new Stack(H - K - 2, (ASN1Sequence) authData.get(nextEntry));
	nextEntry++;

	treehash = new Treehash[H - K];
	for (int h = 0; h < H - K; h++) {
	    treehash[h] = new Treehash(stack, (ASN1Sequence) authData
		    .get(nextEntry));
	    nextEntry++;
	}

	retain = new Stack[K - 1];
	for (int h = 0; h < K - 1; h++) {
	    retain[h] = new Stack((1 << K - 1 - h) - 1, (ASN1Sequence) authData
		    .get(nextEntry));
	    nextEntry++;
	}

	keep = new byte[H - 1][];
	for (int i = 0; i < H - 1; i++) {
	    keep[i] = ((ASN1OctetString) authData.get(nextEntry))
		    .getByteArray();
	    nextEntry++;
	}

	leftLeaf = ((ASN1OctetString) authData.get(nextEntry)).getByteArray();
	nextEntry++;

	tmpNode = ((ASN1OctetString) authData.get(nextEntry)).getByteArray();
	nextEntry++;

	tmpStack = new byte[H + 1][];
	for (int i = 0; i < H + 1; i++) {
	    tmpStack[i] = ((ASN1OctetString) authData.get(nextEntry))
		    .getByteArray();
	    if (tmpStack[i].length == 0)
		tmpStack[i] = null;
	    nextEntry++;
	}

	params = new int[4];
	for (int i = 0; i < 4; i++) {
	    params[i] = ASN1Tools.getFlexiBigInt(
		    (ASN1Integer) authData.get(nextEntry)).intValue();
	    nextEntry++;
	}

    }

    public BDSAuthPath(int H, int K) {
	this.H = H;
	this.K = K;
    }

    public void setup(MessageDigest md, OTS ots, PRNG prng, NodeCalc pc) {
	this.md = md;
	this.ots = ots;
	this.prng = prng;
	nodeCalc = pc;
    }

    public byte[] initialize(byte[] initialSeed) {
	initializationSetup();

	for (int i = 0; i < 1 << H; i++)
	    initializationUpdate(i, initialSeed);

	return initializationFinalize();

    }

    // set up initialization
    public void initializationSetup() {

	// set up arrays and stacks
	auth = new byte[H][];

	seed = new byte[H - K][];

	stack = new Stack(H - K - 2);

	treehash = new Treehash[H - K];
	for (int h = 0; h < H - K; h++) {
	    treehash[h] = new Treehash(stack, h);

	}

	keep = new byte[H - 1][];

	retain = new Stack[K - 1];
	for (int h = 0; h < K - 1; h++) {
	    retain[h] = new Stack((1 << K - 1 - h) - 1);
	}

	// set up stack and temp node for construction of tree
	// retain nodes first stored in arrray
	tmpNode = null;
	tmpStack = new byte[H + 1][];

	// params = {currentAuthNodeHeight, currentNextNodeHeight, seedHeight,
	// seedIndex}
	// currentAuthNodeHeight := height where authentication node is needed
	// currentNextNodeHeight := height where next right authentication node
	// is needed
	// seedHeight := height where seed is needed
	// seedIndex := index of seed required on height seedHeight
	// int currentAuthNodeHeight = 0;
	// int currentNextNodeHeight = -1;
	// int seedHeight = 0;
	// int seedIndex = 3;
	params = new int[4];
	params[0] = 0;
	params[1] = -1;
	params[2] = 0;
	params[3] = 3;
    }

    // partiallyConstructTree, requires seed for ith leaf
    public void initializationUpdate(int i, byte[] initialSeed) {

	// store seeds to compute upcoming right nodes
	if (i == params[3] && params[2] < H - K) {
	    seed[params[2]] = ByteUtils.clone(initialSeed);
	    params[2]++;
	    params[3] = 3 * (1 << params[2]);
	}

	// compute next (ith) leaf
	byte[] otsSeed = prng.nextSeed(initialSeed);
	ots.generateKeyPair(otsSeed);
	tmpNode = nodeCalc.getLeaf(ots.getVerificationKey());

	// compute as many ancestors as possible using tailnodes stored on stack
	int height = 0;
	while (tmpStack[height] != null) {

	    // store first authentication path
	    // first right node encountered on each height
	    if (height == params[0]) {
		auth[params[0]] = ByteUtils.clone(tmpNode);
		params[1] = params[0];
		params[0]++;
	    }

	    // store next right authentication nodes
	    // second right node encountered on each height
	    else if (height == params[1] && height < H - K) {
		treehash[params[1]].storeNode(new Node(tmpNode, 0));
	    }

	    // store right nodes on upper heights
	    // all right nodes encountered on heights H-K <= h <= H-2
	    else if (params[0] >= params[1] && height >= H - K
		    && height <= H - 2) {
		retain[height - (H - K)].pushAtBack(new Node(tmpNode, 0));
	    }

	    // compute parent of treeHashStack[height] and node
	    tmpNode = nodeCalc.computeParent(tmpStack[height], tmpNode, height);

	    // remove tail node from stack
	    tmpStack[height] = null;
	    height++;
	}

	// store ancestor on stack
	tmpStack[height] = ByteUtils.clone(tmpNode);

    }

    // completes initialization, returns root
    public byte[] initializationFinalize() {
	return ByteUtils.clone(tmpStack[H]);
    }

    // outputs auth path for leaf s. prepares upcoming auth paths
    public byte[][] update(int s) {

	// 0. update seed
	for (int i = 0; i < H - K; i++) {
	    prng.nextSeed(seed[i]);
	}

	// 1.
	int tau = computeTau(H, s);

	// 2.
	if (tau < H - 1 && (s >>> tau + 1) % 2 == 0) {
	    keep[tau] = ByteUtils.clone(auth[tau]);
	}

	// 3.
	if (tau == 0) {
	    // must be set in CMSSSignature
	    auth[0] = leftLeaf;
	}

	// 4.
	else {
	    // a)

	    auth[tau] = nodeCalc.computeParent(auth[tau - 1], keep[tau - 1],
		    tau - 1);
	    // b)
	    for (int h = 0; h < tau; h++) {
		if (h < H - K)
		    auth[h] = treehash[h].getNode().getValue();
		else
		    auth[h] = retain[h - (H - K)].pop().getValue();
	    }

	    // c)
	    if (tau > H - K)
		tau = H - K;
	    for (int h = 0; h < tau; h++) {
		if (s + 1 + 3 * (1 << h) < 1 << H)
		    treehash[h].initialize(seed[h]);
	    }
	}

	// 5.

	for (int u = 1; u <= (H - K) / 2; u++) {

	    // a)
	    int index = -1;
	    int minHeight = Integer.MAX_VALUE;

	    for (int h = 0; h < H - K; h++) {
		if (treehash[h].getHeight() < minHeight) {
		    minHeight = treehash[h].getHeight();
		    index = h;
		}
	    }

	    // b)
	    if (index > -1)
		treehash[index].update(prng, ots, md, nodeCalc);

	}

	// 6.
	return auth;
    }

    public void setLeftLeaf(byte[] leftLeaf) {
	this.leftLeaf = ByteUtils.clone(leftLeaf);
    }

    public byte[][] getAuthPath() {
	return auth;
    }

    private int computeTau(int H, int s) {
	if (s % 2 == 0)
	    return 0;

	int tau = 0;
	while ((s + 1) % (1 << tau + 1) == 0) {
	    tau++;
	}
	return tau;
    }

    public void copy(BDSAuthPath otherAuth) {
	for (int i = 0; i < auth.length; i++) {
	    auth[i] = ByteUtils.clone(otherAuth.auth[i]);
	}

	for (int i = 0; i < seed.length; i++) {
	    seed[i] = ByteUtils.clone(otherAuth.seed[i]);
	}

	// copy stack
	stack.copy(otherAuth.stack);

	// copy treehash
	for (int i = 0; i < treehash.length; i++) {
	    treehash[i].copy(otherAuth.treehash[i]);
	}

	// copy stack
	for (int i = 0; i < retain.length; i++) {
	    retain[i].copy(otherAuth.retain[i]);
	}

	for (int i = 0; i < keep.length; i++) {
	    keep[i] = ByteUtils.clone(otherAuth.keep[i]);
	}

	leftLeaf = ByteUtils.clone(otherAuth.leftLeaf);

	// variables for initializeUpdate
	tmpNode = ByteUtils.clone(otherAuth.tmpNode);

	for (int i = 0; i < tmpStack.length; i++) {
	    tmpStack[i] = ByteUtils.clone(otherAuth.tmpStack[i]);
	}

	for (int i = 0; i < params.length; i++) {
	    params[i] = otherAuth.params[i];
	}
    }

    // TODO
    public boolean equals(BDSAuthPath otherAuth) {
	return true;
    }

    /**
     * @return a human readable form of the authentication path
     */
    public String toString() {
	String result;

	if (auth[0] == null || auth[0].length == 0)
	    result = "  authentication path      : " + "(0, null)" + "\n";
	else
	    result = "  authentication path      : " + "(0, "
		    + ByteUtils.toHexString(auth[0]) + ")\n";
	for (int h = 1; h < H; h++) {
	    if (auth[h] == null || auth[h].length == 0)
		result += "                             " + "(" + h + ", null)"
			+ "\n";
	    else
		result += "                             " + "(" + h + ", "
			+ ByteUtils.toHexString(auth[h]) + ")\n";
	}

	if (seed[0] == null || seed[0].length == 0)
	    result += "  seeds                    : " + "(0, null)" + "\n";
	else
	    result += "  seeds                    : " + "(0, "
		    + ByteUtils.toHexString(seed[0]) + ") \n";
	for (int h = 1; h < H - K; h++) {
	    if (seed[h] == null || seed[h].length == 0)
		result += "                             " + "(" + h + ", null)"
			+ "\n";
	    else
		result += "                             " + "(" + h + ", "
			+ ByteUtils.toHexString(seed[h]) + ") \n";
	}

	result += "  tailnodes on stack       : " + stack.toString();

	for (int h = 0; h < H - K; h++) {
	    result += "  treehash[" + h + "]: \n" + treehash[h].toString();
	}

	for (int h = 0; h < K - 1; h++) {
	    result += "  retain[" + (h + H - K) + "]                : "
		    + retain[h].toString();
	}

	if (keep[0] == null || keep[0].length == 0)
	    result += "  keep                     : " + "(0, null)" + "\n";
	else
	    result += "  keep                     : " + "(0, "
		    + ByteUtils.toHexString(keep[0]) + ") \n";
	for (int h = 1; h < H - 1; h++) {
	    if (keep[h] == null || keep[h].length == 0)
		result += "                           : " + "(" + h + ", null)"
			+ "\n";
	    else
		result += "                           : " + "(" + h + ", "
			+ ByteUtils.toHexString(keep[h]) + ") \n";
	}

	if (leftLeaf == null || leftLeaf.length == 0)
	    result += "  left leaf                : " + "null" + "\n";
	else
	    result += "  left leaf                : "
		    + ByteUtils.toHexString(leftLeaf) + "\n";

	if (tmpNode == null || tmpNode.length == 0)
	    result += "  temp node                : " + "null" + "\n";
	else
	    result += "  temp node                : "
		    + ByteUtils.toHexString(tmpNode) + "\n";

	if (tmpStack[0] == null || tmpStack[0].length == 0)
	    result += "  temp stack               : " + "(0, null)" + "\n";
	else
	    result += "  temp stack               : " + "(0, "
		    + ByteUtils.toHexString(tmpStack[0]) + ") \n";
	for (int h = 1; h < H; h++) {
	    if (tmpStack[h] == null || tmpStack[h].length == 0)
		result += "                           : " + "(" + h + ", null)"
			+ "\n";
	    else
		result += "                           : " + "(" + h + ", "
			+ ByteUtils.toHexString(tmpStack[h]) + ") \n";
	}
	return result;
    }

    /**
     * Return the data to encode the authentication path in SubjectPublicKeyInfo
     * structure.
     * <p>
     * The ASN.1 definition of BDSAuthPath
     * 
     * <pre>
     *    BDSAuthPath ::= SEQUENCE {
     *      H                             INTEGER                     -- height of tree
     *      K                             INTEGER                     -- nodes close to root to store    
     *      auth                          SEQUENCE OF OCTET STRING    -- current authentication path
     *      seed                          SEQUENCE OF OCTET STRING    -- current seeds to compute upcoming right nodes
     *      stack                         STACK                       -- stack
     *      treehash                      SEQUENCE OF TREEHASH        -- treehash instances
     *      retain                        SEQUENCE OF STACK           -- right nodes close to the root
     *      keep                          SEQUENCE OF OCTET STRING    -- nodes to efficiently compute left nodes
     *      leftLeaf                      OCTET STRING                -- stored left leaf to efficiently compute left nodes
     *      tmpNode                       OCTET STRING                -- temp node to construct tree
     *      tmpStack                      SEQUENCE OF OCTET STRING    -- temp stack to construct tree
     *      params                        SEQUENCE OF INTEGER         -- to decide which nodes to store during initialization
     *    }
     *      
     *    TREEHASH ::= SEQUENCE {
     *      node                          NODE                        -- node stored by this instance
     *      seed                          OCTET STRING                -- seed to compute next leaf
     *      currentHeight                 INTEGER                     -- height of lowest tailnode stored by this instance
     *      targetHeight                  INTEGER                     -- height of authentication node computed by this instance
     *      nodesOnStack                  INTEGER                     -- number of nodes stored on stack by this instance
     *    }
     *    
     *    STACK ::= SEQUENCE {
     *      tailnodes                     SEQUENCE OF NODE            -- tailnodes
     *      index                         INTEGER                     -- index of top node on stack
     *    }
     *    
     *    NODE ::= SEQUENCE {
     *      value                         OCTET STRING                -- node value
     *      height                        INTEGER                     -- height of node in tree
     *    }
     *    
     * </pre>
     * 
     * @return the keyData to encode in the SubjectPublicKeyInfo structure
     */
    public ASN1Sequence getASN1() {

	ASN1Sequence authData = new ASN1Sequence();

	authData.add(new ASN1Integer(H));
	authData.add(new ASN1Integer(K));

	for (int i = 0; i < H; i++) {
	    authData.add(new ASN1OctetString(auth[i]));
	}
	for (int i = 0; i < H - K; i++) {
	    authData.add(new ASN1OctetString(seed[i]));
	}

	authData.add(stack.getASN1());

	for (int i = 0; i < H - K; i++) {
	    authData.add(treehash[i].getASN1());
	}
	for (int i = 0; i < K - 1; i++) {
	    authData.add(retain[i].getASN1());
	}
	for (int i = 0; i < H - 1; i++) {
	    authData.add(new ASN1OctetString(keep[i]));
	}

	authData.add(new ASN1OctetString(leftLeaf));

	authData.add(new ASN1OctetString(tmpNode));
	for (int i = 0; i < H + 1; i++) {
	    if (tmpStack[i] == null)
		authData.add(new ASN1OctetString(new byte[0]));
	    else
		authData.add(new ASN1OctetString(tmpStack[i]));
	}

	for (int i = 0; i < 4; i++)
	    authData.add(new ASN1Integer(params[i]));

	return authData;
    }
}

class Treehash {

    private Node node;

    private byte[] seed;

    private int currentHeight;

    private int targetHeight;

    private Stack stack;

    private int nodesOnStack;

    public Treehash(Stack stack, ASN1Sequence treehashData) {

	ASN1Sequence nodeData = (ASN1Sequence) treehashData.get(0);
	byte[] value = ((ASN1OctetString) nodeData.get(0)).getByteArray();
	int height = ASN1Tools.getFlexiBigInt((ASN1Integer) nodeData.get(1))
		.intValue();

	if (value.length == 0 && height == 0)
	    node = null;
	else
	    node = new Node(value, height);

	seed = ((ASN1OctetString) treehashData.get(1)).getByteArray();

	currentHeight = ASN1Tools.getFlexiBigInt(
		(ASN1Integer) treehashData.get(2)).intValue();
	targetHeight = ASN1Tools.getFlexiBigInt(
		(ASN1Integer) treehashData.get(3)).intValue();
	this.stack = stack;
	nodesOnStack = ASN1Tools.getFlexiBigInt(
		(ASN1Integer) treehashData.get(4)).intValue();

    }

    public Treehash(Stack stack, int targetHeight) {
	currentHeight = Integer.MAX_VALUE;
	this.targetHeight = targetHeight;
	this.stack = stack;
	nodesOnStack = 0;
    }

    public void initialize(byte[] seed) {
	node = null;
	this.seed = ByteUtils.clone(seed);
	currentHeight = targetHeight;
    }

    public void update(PRNG prng, OTS ots, MessageDigest md, NodeCalc pc) {
	byte[] otsSeed = prng.nextSeed(seed);
	ots.generateKeyPair(otsSeed);
	byte[] leaf = pc.getLeaf(ots.getVerificationKey());

	Node tmpNode = new Node(leaf, 0);

	while (tmpNode.getHeight() == stack.topNodeHeight() && nodesOnStack > 0) {
	    tmpNode = new Node(pc.computeParent(stack.pop().getValue(), tmpNode
		    .getValue(), tmpNode.getHeight()), tmpNode.getHeight() + 1);
	    nodesOnStack--;
	}

	// use node stored in treehash instance
	if (node == null)
	    node = new Node(tmpNode.getValue(), tmpNode.getHeight());
	else {
	    if (tmpNode.getHeight() == node.getHeight()) {
		node = new Node(pc.computeParent(node.getValue(), tmpNode
			.getValue(), tmpNode.getHeight()),
			tmpNode.getHeight() + 1);
	    } else {
		stack.push(tmpNode);
		nodesOnStack++;
	    }
	}

	if (node.getHeight() == targetHeight)
	    currentHeight = Integer.MAX_VALUE;
	else
	    currentHeight = tmpNode.getHeight();

    }

    public void storeNode(Node newNode) {
	node = new Node(ByteUtils.clone(newNode.getValue()), newNode
		.getHeight());
    }

    public Node getNode() {
	Node newNode = new Node(ByteUtils.clone(node.getValue()), node
		.getHeight());
	return newNode;
    }

    public int getHeight() {
	return currentHeight;
    }

    public void copy(Treehash otherTreehash) {
	node.copy(otherTreehash.node);
	seed = ByteUtils.clone(otherTreehash.seed);
	currentHeight = otherTreehash.currentHeight;
	targetHeight = otherTreehash.targetHeight;
	stack.copy(otherTreehash.stack);
	nodesOnStack = otherTreehash.nodesOnStack;
    }

    /**
     * @return a human readable form of the treehash instance
     */
    public String toString() {
	String result;

	if (node == null)
	    result = "    node                   : " + "(null, null) \n";
	else
	    result = "    node                   : " + "(" + node.getHeight()
		    + ", " + ByteUtils.toHexString(node.getValue()) + ") \n";

	if (seed == null || seed.length == 0)
	    result += "    seed                   : " + "null" + "\n";
	else
	    result += "    seed                   : "
		    + ByteUtils.toHexString(seed) + "\n";

	result += "    current height         : " + currentHeight + "\n";
	result += "    target height          : " + targetHeight + "\n";
	result += "    nodes on stack         : " + nodesOnStack + "\n";

	return result;
    }

    /**
     * Return the data to encode the treehash instance in SubjectPublicKeyInfo
     * structure.
     * <p>
     * The ASN.1 definition of treehash
     * 
     * <pre>
     *    TREEHASH ::= SEQUENCE {
     *      node                          NODE                        -- node stored by this instance
     *      seed                          OCTET STRING                -- seed to compute next leaf
     *      currentHeight                 INTEGER                     -- height of lowest tailnode stored by this instance
     *      targetHeight                  INTEGER                     -- height of authentication node computed by this instance
     *      nodesOnStack                  INTEGER                     -- number of nodes stored on stack by this instance
     *    }
     * 
     *    NODE ::= SEQUENCE {
     *      value                         OCTET STRING                -- node value
     *      height                        INTEGER                     -- height of node in tree
     *    }
     *    
     * </pre>
     * 
     * @return the keyData to encode in the SubjectPublicKeyInfo structure
     */
    public ASN1Sequence getASN1() {
	ASN1Sequence treehashData = new ASN1Sequence();

	ASN1Sequence nodeData = new ASN1Sequence();
	if (node == null) {
	    nodeData.add(new ASN1OctetString(new byte[0]));
	    nodeData.add(new ASN1Integer(0));
	} else {
	    nodeData.add(new ASN1OctetString(node.getValue()));
	    nodeData.add(new ASN1Integer(node.getHeight()));
	}
	treehashData.add(nodeData);

	treehashData.add(new ASN1OctetString(seed));
	treehashData.add(new ASN1Integer(currentHeight));
	treehashData.add(new ASN1Integer(targetHeight));
	treehashData.add(new ASN1Integer(nodesOnStack));

	return treehashData;
    }

}

class Stack {

    private Node[] tailnodes;
    private int index;

    public Stack(int height, ASN1Sequence stackData) {

	tailnodes = new Node[height];
	for (int i = 0; i < height; i++) {
	    ASN1Sequence nodeData = (ASN1Sequence) stackData.get(i);
	    byte[] value = ((ASN1OctetString) nodeData.get(0)).getByteArray();
	    int nodeHeight = ASN1Tools.getFlexiBigInt(
		    (ASN1Integer) nodeData.get(1)).intValue();

	    if (value.length == 0 && nodeHeight == 0) {
		tailnodes[i] = null;
	    } else {
		tailnodes[i] = new Node(value, nodeHeight);
	    }

	}

	index = ASN1Tools.getFlexiBigInt((ASN1Integer) stackData.get(height))
		.intValue();
    }

    public Stack(int height) {
	index = -1;
	tailnodes = new Node[height];
    }

    public Node pop() {
	Node node = new Node(ByteUtils.clone(tailnodes[index].getValue()),
		tailnodes[index].getHeight());
	index--;
	return node;
    }

    public void push(Node newNode) {
	index++;
	tailnodes[index] = new Node(ByteUtils.clone(newNode.getValue()),
		newNode.getHeight());
    }

    public void pushAtBack(Node newNode) {
	index++;
	tailnodes[tailnodes.length - 1 - index] = new Node(ByteUtils
		.clone(newNode.getValue()), newNode.getHeight());
    }

    public int topNodeHeight() {
	if (index == -1)
	    return -1;
	return tailnodes[index].getHeight();
    }

    public void copy(Stack otherStack) {
	for (int i = 0; i < tailnodes.length; i++) {
	    if (otherStack.tailnodes[i] != null)
		tailnodes[i].copy(otherStack.tailnodes[i]);
	}
	index = otherStack.index;
    }

    /**
     * @return a human readable form of the stack
     */
    public String toString() {
	String result = "";

	if (tailnodes == null || index < 0)
	    result += "(0, null, null)" + "\n";
	else if (tailnodes[0] == null || index < 0)
	    result += "(0, null, null)" + "\n";
	else
	    result += "(0, " + tailnodes[0].getHeight() + ", "
		    + ByteUtils.toHexString(tailnodes[0].getValue()) + ") \n";

	for (int h = 1; h < tailnodes.length; h++) {
	    if (tailnodes[h] == null || index < h)
		result += "                             (" + h
			+ ", null, null) \n";
	    else
		result += "                             (" + h + ", "
			+ tailnodes[h].getHeight() + ", "
			+ ByteUtils.toHexString(tailnodes[h].getValue())
			+ ") \n";
	}
	return result;
    }

    /**
     * Return the data to encode the stack in SubjectPublicKeyInfo structure.
     * <p>
     * The ASN.1 definition of STACK
     * 
     * <pre>
     *    STACK ::= SEQUENCE {
     *      tailnodes                     SEQUENCE OF NODE            -- tailnodes
     *      index                         INTEGER                     -- index of top node on stack
     *    }
     *    
     *    NODE ::= SEQUENCE {
     *      value                         OCTET STRING                -- node value
     *      height                        INTEGER                     -- height of node in tree
     *    }
     *    
     * </pre>
     * 
     * @return the keyData to encode in the SubjectPublicKeyInfo structure
     */
    public ASN1Sequence getASN1() {

	ASN1Sequence stackData = new ASN1Sequence();

	for (int i = 0; i < tailnodes.length; i++) {
	    ASN1Sequence nodeData = new ASN1Sequence();
	    if (tailnodes[i] == null) {
		nodeData.add(new ASN1OctetString(new byte[0]));
		nodeData.add(new ASN1Integer(0));
	    } else {
		nodeData.add(new ASN1OctetString(tailnodes[i].getValue()));
		nodeData.add(new ASN1Integer(tailnodes[i].getHeight()));
	    }
	    stackData.add(nodeData);
	}

	stackData.add(new ASN1Integer(index));

	return stackData;
    }

}

class Node {

    private byte[] value;
    private int height;

    public Node(byte[] value, int height) {
	this.value = value;
	this.height = height;
    }

    public byte[] getValue() {
	return value;
    }

    public int getHeight() {
	return height;
    }

    public void copy(Node otherNode) {
	value = ByteUtils.clone(otherNode.value);
	height = otherNode.height;
    }

}
