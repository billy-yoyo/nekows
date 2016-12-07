package haxecord.nekows;
import haxe.io.Bytes;

/**
 * ...
 * @author Billy & Kar
 */
class WebSocketMessage
{
	public var source:WebSocket;
	public var data:Bytes;
	public var opcode:OpCode;

	public function new(source:WebSocket, data:Bytes, opcode:OpCode) 
	{
		this.source = source;
		this.data = data;
		this.opcode = opcode;
	}
	
}