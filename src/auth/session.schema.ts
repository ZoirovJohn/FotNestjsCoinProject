import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';

@Schema({ timestamps: true })
export class Session {
  @Prop({ required: true, index: true }) userId: string;
  @Prop({ required: true }) refreshTokenHash: string; // sha256(refreshJWT)
  @Prop() userAgent?: string;
  @Prop() ip?: string;
  @Prop() deviceId?: string;
  @Prop({ required: true }) expiresAt: Date;
  @Prop() revokedAt?: Date;
  @Prop() replacedBy?: string;
}
export const SessionSchema = SchemaFactory.createForClass(Session);
