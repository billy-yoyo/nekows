package haxecord.nekows;
import haxe.io.Bytes;

/**
 * ...
 * @author Billy & Kar
 */
class WebSocketFrame
{
	public var final:Bool;
	public var opcode:OpCode;
	public var data:Bytes;
	public var maskKey:Bytes;

	public function new(final:Bool, opcode:OpCode, data:Bytes, ?maskKey:Bytes) 
	{
		this.final = final;
		this.opcode = opcode;
		this.data = data;
		this.maskKey = maskKey;
	}
	
}