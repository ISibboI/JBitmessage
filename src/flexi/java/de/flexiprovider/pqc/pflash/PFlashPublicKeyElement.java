package de.flexiprovider.pqc.pflash;

import de.flexiprovider.common.math.linearalgebra.GF2mMatrix;
import de.flexiprovider.common.math.linearalgebra.GF2mVector;

public class PFlashPublicKeyElement {
	
	private GF2mMatrix Q_Matrix;
	
	private GF2mVector P_Vector;
	
	private int R; 

	public PFlashPublicKeyElement(GF2mMatrix Q_Matrix, GF2mVector P_Vector, int R){
		this.Q_Matrix=Q_Matrix;
		this.P_Vector=P_Vector;
		this.R = R;
	}
	
	public GF2mMatrix getQ_Matrix(){
		return Q_Matrix;
	}
	
	public GF2mVector getP_Vector(){
		return P_Vector;
	}
	
	public int getR(){
		return R;
	}
}
