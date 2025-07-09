namespace Pode
{
    public class Http2Frame
    {
        public int Length { get; set; }
        public byte Type { get; set; }
        public byte Flags { get; set; }
        public int StreamId { get; set; }
        public byte[] Payload { get; set; }
    }
}